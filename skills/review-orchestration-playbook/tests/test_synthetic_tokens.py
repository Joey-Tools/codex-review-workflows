from __future__ import annotations

import base64
import contextlib
import errno
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
THIN_SKILL_ROOT = SCRIPTS.parents[1] / "synthetic-token-fixtures"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import cli, synthetic_tokens, workspace  # noqa: E402
from review_runtime.common import ReviewError  # noqa: E402


EXPECTED_PUBLIC_VALUES = (
    "codex_public_synth_v1_access_a",
    "codex_public_synth_v1_access_b",
    "codex_public_synth_v1_access_expired",
    "codex_public_synth_v1_refresh_a",
    "codex_public_synth_v1_refresh_b",
    "codex_public_synth_v1_refresh_consumed",
    "codex_public_synth_v1_id_a",
    "codex_public_synth_v1_id_b",
    "codex_public_synth_v1_api_key_a",
    "codex_public_synth_v1_bearer_a",
)
AUTHORING_VALUES = tuple(
    token.value.decode("ascii")
    for token in synthetic_tokens.load_catalog().authoring_tokens
)
LEGACY_A = "HistoricalFixtureAccessA9Z8Y7"
LEGACY_B = "HistoricalFixtureRefreshB8Y7X6"
LEGACY_PRINTABLE = "Historical fixture(v1)|" + r"value,with`\punctuation"
GITHUB_LEGACY = "ghp_" + "A" * 36
JWT_LEGACY = "eyJ" + "A" * 12 + "." + "B" * 12 + "." + "C" * 12
HIGH_ENTROPY = b"Aa9!" + b"Bb8@" + b"Cc7#" + b"Dd6$" + b"Ee5%"


def reduction_secret(rule: str, marker: bytes = b"A") -> bytes:
    if len(marker) != 1 or not marker.isalpha():
        raise ValueError("marker must be one ASCII letter")
    if rule == "generic-secret-assignment":
        return b"RuntimeOpaque" + marker * 16 + b"9!"
    if rule == "jwt":
        return b"eyJ" + marker * 12 + b"." + marker * 12 + b"." + marker * 12
    if rule == "github-token":
        return b"ghp_" + marker * 36
    if rule == "private-key":
        return (
            b"-----BEGIN "
            + b"PRIVATE KEY-----\n"
            + marker * 64
            + b"\n-----END "
            + b"PRIVATE KEY-----"
        )
    raise ValueError(f"unsupported secret reduction rule: {rule}")


def reduction_fixture(rule: str, marker: bytes = b"A") -> str:
    value = reduction_secret(rule, marker).decode("ascii")
    if rule == "private-key":
        return value + "\n"
    return assignment_text("access_token", value)


def rhs_proof_boundary_payloads() -> tuple[bytes, bytes, bytes, bytes]:
    candidate = reduction_secret("github-token", b"C")
    assignment_start = 200
    prefix = b"x" * (assignment_start - 1) + b"\n"

    unsafe_candidate_start = 400
    continued = b"api_token = prefix + /*"
    provider_prefix = b'*/ "wrap/'
    unsafe = (
        prefix
        + continued
        + b"x"
        * (unsafe_candidate_start - len(prefix) - len(continued) - len(provider_prefix))
        + provider_prefix
        + candidate
        + b'+alpha"\n'
    )

    remote_candidate_start = 500
    safe_assignment = b'api_token = "placeholder"\nstate = "expired"\n'
    safe_prefix = prefix + safe_assignment + b"#"
    safe = (
        safe_prefix
        + b"x" * (remote_candidate_start - len(safe_prefix) - 1)
        + b"\n"
        + candidate
        + b"\n"
    )
    ordinary_prefix = prefix + safe_assignment + b"#"
    ordinary = ordinary_prefix + b"x" * (520 - len(ordinary_prefix) - 1) + b"\n"
    return candidate, unsafe, safe, ordinary


def assignment_bytes(key: bytes, value: bytes) -> bytes:
    return key + b' = "' + value + b'"'


def assignment_text(key: str, value: str) -> str:
    return f'{key} = "{value}"\n'


def legacy_value_base64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def git(repo: pathlib.Path, *args: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(repo), *args),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def catalog_payload() -> dict[str, object]:
    return json.loads(synthetic_tokens.CATALOG_PATH.read_text(encoding="utf-8"))


def legacy_catalog(
    *,
    values: tuple[str, ...] = (LEGACY_A, LEGACY_B),
    rule: str = "generic-secret-assignment",
):
    payload = catalog_payload()
    payload["legacy_exemptions"] = [
        {
            "id": "historical-fixtures",
            "repository": "example/project",
            "verified_master_tip": "a" * 40,
            "match": "non-increasing-global-count",
            "values": [
                {
                    "id": f"historical-{index}",
                    "rule": rule,
                    "value_base64": legacy_value_base64(value),
                    "containing_commit": "b" * 40,
                    "source_occurrences": 1,
                }
                for index, value in enumerate(values, start=1)
            ],
        }
    ]
    return synthetic_tokens.parse_catalog_bytes(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )


def accepted_legacy_value(value: str, *, rule: str):
    encoded = value.encode("ascii")
    return synthetic_tokens.AcceptedSyntheticValue(
        kind="legacy",
        catalog_version="test-v1",
        identifier="historical-value",
        rule=rule,
        value=encoded,
        value_sha256=hashlib.sha256(encoded).hexdigest(),
        value_length=len(encoded),
        exemption_id="historical-fixtures",
    )


class PublicPoolScannerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = synthetic_tokens.load_catalog()
        cls.accepted = synthetic_tokens.accepted_authoring_values(cls.catalog)

    def test_public_v1_pool_is_exactly_the_ten_documented_values(self) -> None:
        if self.catalog.pool_version != "public-example-v1":
            self.skipTest("active downstream catalog replaces the public example pool")
        self.assertEqual(self.catalog.schema_version, 1)
        self.assertEqual(self.catalog.pool_version, "public-example-v1")
        self.assertEqual(
            tuple(
                token.value.decode("ascii") for token in self.catalog.authoring_tokens
            ),
            EXPECTED_PUBLIC_VALUES,
        )
        self.assertEqual(
            len({token.identifier for token in self.catalog.authoring_tokens}), 10
        )
        self.assertEqual(
            tuple(item.identifier for item in self.catalog.legacy_exemptions),
            (),
        )

    def test_each_exact_pool_value_suppresses_only_generic_assignment(self) -> None:
        for descriptor in self.accepted:
            with self.subTest(token=descriptor.identifier):
                scan = workspace._scan_secret_value(
                    b'access_token = "' + descriptor.value + b'"',
                    accepted_values=self.accepted,
                )
                self.assertIsNone(scan.blocking_rule)
                self.assertEqual(scan.accepted_counts[descriptor], 1)

                plain = workspace._scan_secret_value(
                    b"prefix " + descriptor.value + b" suffix",
                    accepted_values=self.accepted,
                )
                self.assertIsNone(plain.blocking_rule)
                self.assertFalse(plain.accepted_counts)

        provider = b"ghp_" + b"A" * 36
        scan = workspace._scan_secret_value(
            b'access_token = "'
            + self.accepted[0].value
            + b'"\nprovider = "'
            + provider
            + b'"\n',
            accepted_values=self.accepted,
        )
        self.assertEqual(scan.blocking_rule, "github-token")
        self.assertFalse(scan.accepted_counts)

    def test_each_pool_value_is_captured_once_in_supported_assignments(self) -> None:
        keys = {
            "access": b"access_token",
            "refresh": b"refresh_token",
            "id": b"id_token",
            "api-key": b"api_key",
            "bearer": b"bearer_token",
        }
        accepted_by_id = {item.identifier: item for item in self.accepted}
        for token in self.catalog.authoring_tokens:
            accepted = accepted_by_id[token.identifier]
            key = keys[token.role]
            probes = (
                key + b' = "' + token.value + b'"\n',
                key + b" = '" + token.value + b"'\r\n",
                key + b" = " + token.value,
                key + b" = " + token.value + b"\n",
                key + b" = " + token.value + b"\r\n",
            )
            for index, probe in enumerate(probes):
                with self.subTest(token=token.identifier, probe=index):
                    scan = workspace._scan_secret_value(
                        probe,
                        accepted_values=(accepted,),
                    )
                    self.assertIsNone(scan.blocking_rule)
                    self.assertEqual(
                        scan.accepted_counts,
                        Counter({accepted: 1}),
                    )

    def test_unquoted_pool_value_requires_a_complete_logical_rhs(self) -> None:
        accepted = self.accepted[0]
        value = accepted.value
        adjacent = b"ActualOpaqueSecretA9Z8Y7"
        blocking_cases = (
            (
                "yaml-continuation",
                b"api_key: " + value + b"\n  " + adjacent + b"\n",
                False,
            ),
            (
                "nested-yaml-continuation",
                b"fixtures:\n  api_key: " + value + b"\n    " + adjacent + b"\n",
                False,
            ),
            (
                "sequence-yaml-continuation",
                b"- api_key: " + value + b"\n    " + adjacent + b"\n",
                False,
            ),
            (
                "commented-yaml-continuation",
                b"api_key: " + value + b" # fixture\n  " + adjacent + b"\n",
                False,
            ),
            (
                "ambiguous-inline-comment",
                b"api_key: " + value + b" # fixture\n",
                False,
            ),
            (
                "blank-line-yaml-continuation",
                b"api_key: " + value + b"\n\n  " + adjacent + b"\n",
                False,
            ),
            (
                "crlf-yaml-continuation",
                b"api_key: " + value + b"\r\n  " + adjacent + b"\r\n",
                False,
            ),
            (
                "same-indent-operator-continuation",
                b"configure(\n    api_key = "
                + value
                + b"\n    + "
                + adjacent
                + b"\n)\n",
                False,
            ),
            (
                "shell-line-continuation",
                b"access_token=" + value + b"\\\n" + adjacent + b"\n",
                False,
            ),
            (
                "shell-crlf-continuation",
                b"access_token=" + value + b"\\\r\n" + adjacent + b"\r\n",
                False,
            ),
            (
                "double-quoted-word-concatenation",
                b"access_token=" + value + b'"' + adjacent + b'"\n',
                False,
            ),
            (
                "single-quoted-word-concatenation",
                b"access_token=" + value + b"'" + adjacent + b"'\n",
                False,
            ),
            (
                "parameter-expansion-concatenation",
                b"access_token=" + value + b"${ACTUAL_SECRET}\n",
                False,
            ),
            (
                "command-substitution-concatenation",
                b"access_token=" + value + b"`read_actual_secret`\n",
                False,
            ),
            (
                "diff-yaml-continuation",
                b"+api_key: " + value + b"\n+  " + adjacent + b"\n",
                True,
            ),
            (
                "diff-operator-continuation",
                b"+    api_key = " + value + b"\n+    + " + adjacent + b"\n",
                True,
            ),
            (
                "diff-shell-continuation",
                b"+access_token=" + value + b"\\\n+" + adjacent + b"\n",
                True,
            ),
            (
                "ambiguous-semicolon",
                b"api_key: " + value + b" ; " + adjacent + b"\n",
                False,
            ),
            (
                "tab-indentation",
                b"api_key: " + value + b"\n\t" + adjacent + b"\n",
                False,
            ),
            (
                "bounded-comment-inspection",
                b"api_key: "
                + value
                + b" #"
                + b"x" * (workspace.MAX_SECRET_ASSIGNMENT_TRAILING_BYTES + 1)
                + b"\nstate: expired\n",
                False,
            ),
        )
        for label, payload, diff_surface in blocking_cases:
            with self.subTest(case=label):
                scan = workspace._scan_secret_value(
                    payload,
                    accepted_values=(accepted,),
                    diff_surface=diff_surface,
                )
                self.assertEqual(scan.blocking_rule, "generic-secret-assignment")
                self.assertFalse(scan.accepted_counts)

        safe_cases = (
            ("next-root-key", b"api_key: " + value + b"\nstate: expired\n", False),
            (
                "next-nested-key",
                b"fixtures:\n  api_key: " + value + b"\n  state: expired\n",
                False,
            ),
            (
                "next-sequence-key",
                b"- api_key: " + value + b"\n  state: expired\n",
                False,
            ),
            (
                "diff-next-key",
                b"+api_key: " + value + b"\n+state: expired\n",
                True,
            ),
            (
                "diff-metadata-boundary",
                b"+api_key: " + value + b"\n@@ -1 +1 @@\n",
                True,
            ),
        )
        for label, payload, diff_surface in safe_cases:
            with self.subTest(case=label):
                scan = workspace._scan_secret_value(
                    payload,
                    accepted_values=(accepted,),
                    diff_surface=diff_surface,
                )
                self.assertIsNone(scan.blocking_rule)
                self.assertEqual(scan.accepted_counts, Counter({accepted: 1}))

    def test_unquoted_continuation_is_blocked_across_stream_boundary(
        self,
    ) -> None:
        accepted = self.accepted[0]
        assignment_prefix = b"api_key: "
        first_read = 1024 * 1024
        committed_end = first_read - workspace.STREAM_SCAN_OVERLAP
        candidate_end = committed_end - 16
        line_start = candidate_end - len(assignment_prefix) - len(accepted.value)
        prefix = b"x\n" * (line_start // 2)
        if len(prefix) < line_start:
            prefix += b"\n"
        self.assertEqual(len(prefix), line_start)
        for label, continuation in (
            ("yaml", b"\n  ActualOpaqueSecretA9Z8Y7\n"),
            ("shell", b"\\\nActualOpaqueSecretA9Z8Y7\n"),
        ):
            with self.subTest(case=label):
                payload = (
                    prefix
                    + assignment_prefix
                    + accepted.value
                    + continuation
                    + b"x" * workspace.STREAM_SCAN_OVERLAP
                )

                scan = workspace._stream_secret_scan(
                    io.BytesIO(payload),
                    size=len(payload),
                    accepted_values=(accepted,),
                )

                self.assertEqual(scan.blocking_rule, "generic-secret-assignment")
                self.assertFalse(scan.accepted_counts)

    def test_runtime_python_sources_pass_their_own_secret_scanner(self) -> None:
        runtime_root = pathlib.Path(workspace.__file__).resolve().parent
        for path in sorted(runtime_root.glob("*.py")):
            with self.subTest(path=path.name):
                scan = workspace._scan_secret_value(
                    path.read_bytes(),
                    accepted_values=self.accepted,
                )
                self.assertIsNone(scan.blocking_rule)

    def test_mutated_pool_values_remain_blocked(self) -> None:
        original = AUTHORING_VALUES[0]
        variants = {
            "suffix": original + "_extra",
            "prefix": "extra_" + original,
            "embedded": "prefix" + original + "suffix",
            "case": original.upper(),
            "whitespace": original.replace("_", " ", 1),
            "escape": original.replace("_", r"\x5f", 1),
            "unicode": original.replace("o", "\N{CYRILLIC SMALL LETTER O}", 1),
        }
        for label, value in variants.items():
            with self.subTest(variant=label):
                scan = workspace._scan_secret_value(
                    f'access_token = "{value}"'.encode("utf-8"),
                    accepted_values=self.accepted,
                )
                self.assertEqual(scan.blocking_rule, "generic-secret-assignment")
                self.assertFalse(scan.accepted_counts)

    def test_other_scanner_rules_and_adjacent_values_are_not_suppressed(self) -> None:
        cases = (
            ("github", "github-token", b"ghp_" + b"A" * 36),
            (
                "jwt",
                "jwt",
                b"eyJ" + b"A" * 12 + b"." + b"B" * 12 + b"." + b"C" * 12,
            ),
            (
                "private-key",
                "private-key",
                b"-----BEGIN " + b"PRIVATE KEY-----",
            ),
            ("provider", "openai-key", b"sk-" + b"D" * 40),
            (
                "high-entropy",
                "generic-secret-assignment",
                assignment_bytes(b"password", HIGH_ENTROPY),
            ),
        )
        for label, expected_rule, payload in cases:
            with self.subTest(case=label):
                scan = workspace._scan_secret_value(
                    payload,
                    accepted_values=self.accepted,
                )
                self.assertEqual(scan.blocking_rule, expected_rule)

        adjacent = workspace._scan_secret_value(
            assignment_bytes(b"access_token", self.accepted[0].value)
            + b"\n"
            + assignment_bytes(b"refresh_token", HIGH_ENTROPY),
            accepted_values=self.accepted,
        )
        self.assertEqual(adjacent.blocking_rule, "generic-secret-assignment")
        self.assertEqual(adjacent.accepted_counts[self.accepted[0]], 1)

    def test_id_token_assignments_are_scanned(self) -> None:
        unknown = workspace._scan_secret_value(
            assignment_bytes(b"id_token", b"UnknownIdTokenA9Z8Y7X6")
        )
        self.assertEqual(unknown.blocking_rule, "generic-secret-assignment")
        accepted = next(token for token in self.accepted if token.identifier == "id-a")
        exact = workspace._scan_secret_value(
            assignment_bytes(b"id_token", accepted.value),
            accepted_values=self.accepted,
        )
        self.assertIsNone(exact.blocking_rule)
        self.assertEqual(exact.accepted_counts[accepted], 1)

    def test_provider_specific_legacy_acceptance_suppresses_duplicate_assignment(
        self,
    ) -> None:
        accepted = accepted_legacy_value(GITHUB_LEGACY, rule="github-token")
        scan = workspace._scan_secret_value(
            assignment_bytes(b"access_token", GITHUB_LEGACY.encode("ascii")),
            accepted_values=(accepted,),
        )
        self.assertIsNone(scan.blocking_rule)
        self.assertEqual(scan.accepted_counts[accepted], 1)

        adjacent = workspace._scan_secret_value(
            assignment_bytes(
                b"access_token",
                GITHUB_LEGACY.encode("ascii") + b".adjacent",
            ),
            accepted_values=(accepted,),
        )
        self.assertEqual(adjacent.blocking_rule, "generic-secret-assignment")
        self.assertEqual(adjacent.accepted_counts[accepted], 1)

    def test_provider_specific_legacy_acceptance_survives_stream_boundary(self) -> None:
        accepted = accepted_legacy_value(GITHUB_LEGACY, rule="github-token")
        candidate = GITHUB_LEGACY.encode("ascii")
        assignment_prefix = b'access_token = "'
        first_read = (
            workspace.MAX_SECRET_PREFIX_PROOF_BYTES + workspace.STREAM_SCAN_OVERLAP
        )
        committed_end = first_read - workspace.STREAM_SCAN_OVERLAP
        candidate_start = committed_end - len(candidate)
        payload = (
            b"x" * (candidate_start - len(assignment_prefix))
            + assignment_prefix
            + candidate
            + b'"\nstate = "expired"\n'
            + b"x" * workspace.STREAM_SCAN_OVERLAP
        )
        event_budget = workspace.SecretScanBudget(3)
        with mock.patch.object(
            workspace.SecretScanBudget,
            "default",
            return_value=event_budget,
        ):
            scan = workspace._stream_secret_scan(
                io.BytesIO(payload),
                size=len(payload),
                accepted_values=(accepted,),
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )
        self.assertIsNone(scan.blocking_rule)
        self.assertEqual(scan.accepted_counts[accepted], 1)
        self.assertEqual(len(scan.blocking_candidates), 0)
        self.assertEqual(event_budget.remaining, 0)

    def test_legacy_raw_occurrences_cross_stream_boundaries_and_survive_blocking(
        self,
    ) -> None:
        accepted = accepted_legacy_value(LEGACY_A, rule="generic-secret-assignment")
        raw = LEGACY_A.encode("ascii")
        boundary = 1024 * 1024
        blocking = assignment_bytes(b"password", HIGH_ENTROPY)
        payload = (
            blocking
            + b"x" * (boundary - len(raw) // 2 - len(blocking))
            + raw
            + b"\x00tail"
        )
        scan = workspace._stream_secret_scan(
            io.BytesIO(payload),
            size=len(payload),
            raw_occurrence_values=(accepted,),
        )
        self.assertEqual(scan.blocking_rule, "generic-secret-assignment")
        self.assertEqual(scan.raw_occurrence_counts[accepted], 1)
        self.assertEqual(scan.unembedded_occurrence_counts[accepted], 1)

        encoded_storage = legacy_value_base64(LEGACY_A).encode("ascii")
        encoded_scan = workspace._scan_secret_value(
            assignment_bytes(b"access_token", encoded_storage),
            accepted_values=(accepted,),
        )
        self.assertEqual(
            encoded_scan.blocking_rule,
            "generic-secret-assignment",
        )
        self.assertFalse(encoded_scan.accepted_counts)

    def test_legacy_raw_occurrence_and_search_budgets_fail_closed(self) -> None:
        accepted = accepted_legacy_value(LEGACY_A, rule="generic-secret-assignment")
        raw = LEGACY_A.encode("ascii")
        with (
            mock.patch.object(workspace, "MAX_LEGACY_OCCURRENCE_EVENTS", 1),
            self.assertRaisesRegex(ReviewError, "occurrence limit"),
        ):
            workspace._scan_secret_value(
                raw + b" " + raw,
                raw_occurrence_values=(accepted,),
            )
        with (
            mock.patch.object(workspace, "MAX_LEGACY_SEARCH_BYTES", 1),
            self.assertRaisesRegex(ReviewError, "search limit"),
        ):
            workspace._scan_secret_value(
                raw,
                raw_occurrence_values=(accepted,),
            )

    def test_overlapping_legacy_occurrences_track_unembedded_values_across_chunks(
        self,
    ) -> None:
        longer = "PrefixTag" + LEGACY_A + LEGACY_A + "SuffixTag"
        catalog = legacy_catalog(values=(LEGACY_A, longer))
        accepted = workspace._all_catalog_sensitive_values(catalog)
        by_id = {item.identifier: item for item in accepted}
        boundary = 1024 * 1024
        longer_raw = longer.encode("ascii")
        prefix_size = boundary - len("PrefixTag") - len(LEGACY_A) // 2
        payload = b"x" * prefix_size + longer_raw + b"tail"
        scan = workspace._stream_secret_scan(
            io.BytesIO(payload),
            size=len(payload),
            raw_occurrence_values=accepted,
        )
        short = by_id["historical-1"]
        long = by_id["historical-2"]
        self.assertEqual(scan.raw_occurrence_counts[short], 2)
        self.assertEqual(scan.unembedded_occurrence_counts[short], 0)
        self.assertEqual(scan.raw_occurrence_counts[long], 1)
        self.assertEqual(scan.unembedded_occurrence_counts[long], 1)

        with (
            mock.patch.object(workspace, "MAX_LEGACY_CONTAINMENT_CHECKS", 0),
            self.assertRaisesRegex(ReviewError, "containment limit"),
        ):
            workspace._scan_secret_value(
                longer_raw,
                raw_occurrence_values=accepted,
            )

    def test_overlapping_dynamic_occurrences_share_one_containment_domain(
        self,
    ) -> None:
        short_raw = b"RuntimeOpaque" + b"A" * 16 + b"9!"
        long_raw = b"Prefix" + short_raw + b"Suffix"
        short = workspace._secret_reduction_descriptor(
            short_raw,
            {"generic-secret-assignment"},
        )
        long = workspace._secret_reduction_descriptor(
            long_raw,
            {"generic-secret-assignment"},
        )

        scan = workspace._scan_secret_value(
            long_raw,
            raw_occurrence_values=(short, long),
        )

        self.assertEqual(scan.raw_occurrence_counts[short], 1)
        self.assertEqual(scan.unembedded_occurrence_counts[short], 0)
        self.assertEqual(scan.raw_occurrence_counts[long], 1)
        self.assertEqual(scan.unembedded_occurrence_counts[long], 1)

    def test_dynamic_occurrence_offsets_are_blob_global_across_stream_chunks(
        self,
    ) -> None:
        short_raw = b"RuntimeOpaque" + b"A" * 16 + b"9!"
        long_raw = b"Prefix" + short_raw + b"Suffix"
        short = workspace._secret_reduction_descriptor(
            short_raw,
            {"generic-secret-assignment"},
        )
        long = workspace._secret_reduction_descriptor(
            long_raw,
            {"generic-secret-assignment"},
        )
        long_start = 37
        short_start = long_start + len(long_raw) + 41
        payload = (
            b"x" * long_start
            + long_raw
            + b"y" * (short_start - long_start - len(long_raw))
            + short_raw
        )

        with (
            mock.patch.object(workspace, "MAX_SECRET_PREFIX_PROOF_BYTES", 32),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", 16),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 32),
        ):
            scan = workspace._stream_secret_scan(
                io.BytesIO(payload),
                size=len(payload),
                raw_occurrence_values=(short, long),
                capture_reduction_offsets=True,
            )

        self.assertEqual(
            scan.reduction_occurrence_offsets[short],
            {long_start + len(b"Prefix"), short_start},
        )
        self.assertEqual(
            scan.reduction_unembedded_offsets[short],
            {short_start},
        )
        self.assertEqual(scan.reduction_occurrence_offsets[long], {long_start})
        self.assertEqual(scan.reduction_unembedded_offsets[long], {long_start})

    def test_accepted_quoted_value_requires_a_complete_rhs(self) -> None:
        accepted = self.accepted[0]
        exact_assignment = assignment_bytes(b"access_token", accepted.value)
        adjacent_secret = b'"ActualOpaqueSecretA9Z8Y7"'
        cases = (
            ("implicit-concatenation", exact_assignment + b" " + adjacent_secret),
            ("explicit-concatenation", exact_assignment + b" + " + adjacent_secret),
            ("conditional-fallback", exact_assignment + b" or " + adjacent_secret),
            ("tuple-continuation", exact_assignment + b", " + adjacent_secret),
            (
                "wrapped-tuple-continuation",
                exact_assignment + b", (" + adjacent_secret + b")",
            ),
            (
                "wrapped-list-continuation",
                exact_assignment + b", [" + adjacent_secret + b"]",
            ),
            (
                "trailing-comma-closure-continuation",
                b"identity(" + exact_assignment + b",) + " + adjacent_secret,
            ),
            (
                "colon-unlabeled-argument",
                b'configure(access_token: "'
                + accepted.value
                + b'", '
                + adjacent_secret
                + b")",
            ),
            (
                "newline-concatenation",
                b"configure(" + exact_assignment + b"\n " + adjacent_secret + b")",
            ),
            (
                "line-comment-concatenation",
                b"configure("
                + exact_assignment
                + b" # fixture\n r"
                + adjacent_secret
                + b")",
            ),
            (
                "block-comment-concatenation",
                exact_assignment + b" /* fixture */ " + adjacent_secret,
            ),
            (
                "newline-operator-concatenation",
                b"configure(" + exact_assignment + b"\n + " + adjacent_secret + b")",
            ),
            (
                "floor-division-concatenation",
                exact_assignment + b" // " + adjacent_secret,
            ),
            (
                "newline-floor-division-concatenation",
                b"configure(" + exact_assignment + b"\n // " + adjacent_secret + b")",
            ),
            (
                "diff-floor-division-concatenation",
                b"+configure(\n+    "
                + exact_assignment
                + b"\n+    // "
                + adjacent_secret
                + b"\n+)\n",
            ),
            (
                "unknown-operator-concatenation",
                exact_assignment + b"\n <> " + adjacent_secret,
            ),
            (
                "macro-concatenation",
                exact_assignment + b"\nOPAQUE_VALUE;",
            ),
            (
                "placeholder-concatenation",
                assignment_bytes(b"access_token", b"placeholder_token")
                + b" "
                + adjacent_secret,
            ),
            (
                "json-object-array-unlabeled-value",
                b'[{"access_token": "'
                + accepted.value
                + b'"}, {'
                + adjacent_secret
                + b"}]",
            ),
            (
                "multiline-json-object-array-unlabeled-value",
                b'[{"access_token": "'
                + accepted.value
                + b'"}, {\n  '
                + adjacent_secret
                + b"\n}]",
            ),
            (
                "plain-source-string-concatenation",
                b"payload = '" + exact_assignment + b"' + " + adjacent_secret,
            ),
            (
                "unclosed-call-before-declaration",
                b"configure(" + exact_assignment + b"\ndef test_fixture():\n    pass\n",
            ),
            (
                "multiline-unclosed-call-before-declaration",
                b"configure(\n"
                + exact_assignment
                + b",\ndef test_fixture():\n    pass\n",
            ),
            (
                "spaced-multiline-unclosed-call-before-declaration",
                b"configure(\n "
                + exact_assignment
                + b",\ndef test_fixture():\n    pass\n",
            ),
            (
                "tabbed-multiline-unclosed-call-before-declaration",
                b"configure(\n\t"
                + exact_assignment
                + b",\ndef test_fixture():\n    pass\n",
            ),
            (
                "unclosed-mapping-before-declaration",
                b'{"access_token": "'
                + accepted.value
                + b'"\ndef test_fixture():\n    pass\n',
            ),
            (
                "unclosed-source-wrapper-before-declaration",
                b"payload = (\nb'"
                + exact_assignment
                + b"',\ndef test_fixture():\n    pass\n",
            ),
            (
                "diff-unclosed-call-before-declaration",
                b"+configure(\n+"
                + exact_assignment
                + b",\n+def test_fixture():\n+    pass\n",
            ),
            (
                "diff-unclosed-source-wrapper-before-declaration",
                b"+payload = (\n+b'"
                + exact_assignment
                + b"',\n+def test_fixture():\n+    pass\n",
            ),
            (
                "unclosed-call-after-sibling",
                b"configure(" + exact_assignment + b', state="expired"\n',
            ),
            (
                "unclosed-call-after-sibling-string-closer",
                b"configure(" + exact_assignment + b', state=")"\n',
            ),
            (
                "unclosed-json-after-sibling",
                b'{"access_token": "' + accepted.value + b'", "state": "expired"\n',
            ),
            (
                "unclosed-json-array-after-sibling",
                b'[{"access_token": "' + accepted.value + b'", "state": "expired"}\n',
            ),
            (
                "diff-unclosed-call-after-sibling",
                b"+configure(\n+    " + exact_assignment + b',\n+    state="expired"\n',
            ),
            (
                "source-literal-unclosed-logical-call-after-sibling",
                b"payload = b'configure(" + exact_assignment + b', state="expired"\'\n',
            ),
            (
                "source-literal-missing-outer-quote-after-sibling",
                b"payload = b'configure(" + exact_assignment + b', state="expired")\n',
            ),
            (
                "indented-declaration",
                b'{"access_token": "'
                + accepted.value
                + b'"}\n    def nested_fixture():\n        pass\n',
            ),
            (
                "same-line-declaration",
                b'{"access_token": "'
                + accepted.value
                + b'"} def test_fixture():\n    pass\n',
            ),
            (
                "decorator-is-not-a-proven-boundary",
                b'{"access_token": "'
                + accepted.value
                + b'"}\n@pytest.mark.fixture\ndef test_fixture():\n    pass\n',
            ),
            (
                "identifier-prefix-is-not-def",
                exact_assignment + b"\ndefinitely(test_fixture)\n",
            ),
        )
        for label, payload in cases:
            with self.subTest(case=label):
                scan = workspace._scan_secret_value(
                    payload,
                    accepted_values=self.accepted,
                    diff_surface=label.startswith("diff-"),
                )
                self.assertEqual(scan.blocking_rule, "generic-secret-assignment")

        json_value = workspace._scan_secret_value(
            b'{"access_token": "' + accepted.value + b'", "state": "expired"}',
            accepted_values=self.accepted,
        )
        self.assertIsNone(json_value.blocking_rule)
        self.assertEqual(json_value.accepted_counts[accepted], 1)

        json_object_array = workspace._scan_secret_value(
            b'[{"access_token": "' + accepted.value + b'"}, {"name": "next"}]',
            accepted_values=self.accepted,
        )
        self.assertIsNone(json_object_array.blocking_rule)
        self.assertEqual(json_object_array.accepted_counts[accepted], 1)

        for label, line_break, diff_prefix, diff_surface in (
            ("lf", b"\n", b"", False),
            ("crlf", b"\r\n", b"", False),
            ("diff", b"\n", b"+", True),
        ):
            with self.subTest(json_object_array=label):
                pretty_json = workspace._scan_secret_value(
                    diff_prefix
                    + b'[{"access_token": "'
                    + accepted.value
                    + b'"}, {'
                    + line_break
                    + diff_prefix
                    + b'  "name": "next"'
                    + line_break
                    + diff_prefix
                    + b"}]",
                    accepted_values=self.accepted,
                    diff_surface=diff_surface,
                )
                self.assertIsNone(pretty_json.blocking_rule)
                self.assertEqual(pretty_json.accepted_counts[accepted], 1)

        keyword_argument = workspace._scan_secret_value(
            b'configure(access_token = "' + accepted.value + b'", state = "expired")',
            accepted_values=self.accepted,
        )
        self.assertIsNone(keyword_argument.blocking_rule)
        self.assertEqual(keyword_argument.accepted_counts[accepted], 1)

        source_sibling = workspace._scan_secret_value(
            b"payload = b'configure(" + exact_assignment + b', state="expired")\'\n',
            accepted_values=self.accepted,
        )
        self.assertIsNone(source_sibling.blocking_rule)
        self.assertEqual(source_sibling.accepted_counts[accepted], 1)

        triple_source_sibling = workspace._scan_secret_value(
            b"payload = b'''configure("
            + exact_assignment
            + b", state=\"expired\")'''\n",
            accepted_values=self.accepted,
        )
        self.assertIsNone(triple_source_sibling.blocking_rule)
        self.assertEqual(triple_source_sibling.accepted_counts[accepted], 1)

        physical_source_sibling = workspace._scan_secret_value(
            b"payload = (b'configure(" + exact_assignment + b', state="expired")\')\n',
            accepted_values=self.accepted,
        )
        self.assertIsNone(physical_source_sibling.blocking_rule)
        self.assertEqual(physical_source_sibling.accepted_counts[accepted], 1)

        diff_sibling = workspace._scan_secret_value(
            b"+configure(\n+    " + exact_assignment + b',\n+    state="expired"\n+)\n',
            accepted_values=self.accepted,
            diff_surface=True,
        )
        self.assertIsNone(diff_sibling.blocking_rule)
        self.assertEqual(diff_sibling.accepted_counts[accepted], 1)

        trailing_comma = workspace._scan_secret_value(
            b"configure(" + exact_assignment + b",)",
            accepted_values=self.accepted,
        )
        self.assertIsNone(trailing_comma.blocking_rule)
        self.assertEqual(trailing_comma.accepted_counts[accepted], 1)

        colon_keyword_argument = workspace._scan_secret_value(
            b'configure(access_token: "' + accepted.value + b'", state: "expired")',
            accepted_values=self.accepted,
        )
        self.assertIsNone(colon_keyword_argument.blocking_rule)
        self.assertEqual(colon_keyword_argument.accepted_counts[accepted], 1)

        next_statement = workspace._scan_secret_value(
            exact_assignment + b'\nstate = "expired"\n',
            accepted_values=self.accepted,
        )
        self.assertIsNone(next_statement.blocking_rule)
        self.assertEqual(next_statement.accepted_counts[accepted], 1)

        for label, payload, diff_surface in (
            (
                "standalone-def",
                exact_assignment + b"\ndef test_fixture():\n    pass\n",
                False,
            ),
            (
                "closed-dict-def",
                b'FIXTURE = {\n    "access_token": "'
                + accepted.value
                + b'"\n}\ndef test_fixture():\n    pass\n',
                False,
            ),
            (
                "closed-dict-trailing-comma-class",
                b'FIXTURE = {\n    "access_token": "'
                + accepted.value
                + b'",\n}\nclass FixtureTest:\n    pass\n',
                False,
            ),
            (
                "source-wrapper-async-def",
                b"payload = b'"
                + exact_assignment
                + b"'\n\n# fixture boundary\nasync def test_fixture():\n    pass\n",
                False,
            ),
            (
                "diff-closed-dict-def",
                b'+FIXTURE = {\n+    "access_token": "'
                + accepted.value
                + b'",\n+}\n+def test_fixture():\n+    pass\n',
                True,
            ),
            (
                "diff-standalone-def",
                b"+" + exact_assignment + b"\n+def test_fixture():\n+    pass\n",
                True,
            ),
            (
                "diff-hunk-closed-dict-def",
                b"@@ -10,3 +10,6 @@ fixture\n"
                b'+FIXTURE = {\n+    "access_token": "'
                + accepted.value
                + b'",\n+}\n+class FixtureTest:\n+    pass\n',
                True,
            ),
        ):
            with self.subTest(declaration_boundary=label):
                declaration = workspace._scan_secret_value(
                    payload,
                    accepted_values=self.accepted,
                    diff_surface=diff_surface,
                )
                self.assertIsNone(declaration.blocking_rule)
                self.assertEqual(declaration.accepted_counts[accepted], 1)

        declaration_with_adjacent_secret = workspace._scan_secret_value(
            exact_assignment
            + b'\ndef test_fixture(access_token="UnknownSecret'
            + b'ValueA9Z8Y7"):\n'
            + b"    pass\n",
            accepted_values=self.accepted,
        )
        self.assertEqual(
            declaration_with_adjacent_secret.blocking_rule,
            "generic-secret-assignment",
        )

        declaration_payload = exact_assignment + b"\ndef test_fixture():\n    pass\n"
        incomplete_prefix = workspace._scan_secret_value(
            declaration_payload,
            accepted_values=self.accepted,
            prefix_context_complete=False,
        )
        self.assertEqual(
            incomplete_prefix.blocking_rule,
            "generic-secret-assignment",
        )
        with mock.patch.object(
            workspace,
            "MAX_SECRET_PREFIX_PROOF_BYTES",
            len(exact_assignment),
        ):
            oversized_prefix = workspace._scan_secret_value(
                declaration_payload,
                accepted_values=self.accepted,
            )
        self.assertEqual(
            oversized_prefix.blocking_rule,
            "generic-secret-assignment",
        )
        exhausted_budget = workspace.SecretScanBudget(
            workspace.MAX_SECRET_SCAN_EVENTS,
            remaining_prefix_proof_bytes=0,
        )
        with self.assertRaisesRegex(ReviewError, "prefix proof limit"):
            workspace._scan_secret_value(
                declaration_payload,
                accepted_values=self.accepted,
                _event_budget=exhausted_budget,
            )

        for label, padding_size in (
            ("after-old-first-read", 1024 * 1024 + 512),
            ("inside-old-deferred-overlap", 1024 * 1024 - 128),
        ):
            with self.subTest(stream_declaration_boundary=label):
                padding = b"#" + b"x" * padding_size + b"\n"
                stream_payload = padding + declaration_payload
                stream_scan = workspace._stream_secret_scan(
                    io.BytesIO(stream_payload),
                    size=len(stream_payload),
                    accepted_values=self.accepted,
                )
                self.assertIsNone(stream_scan.blocking_rule)
                self.assertEqual(stream_scan.accepted_counts[accepted], 1)

        class ShortReadStream(io.BytesIO):
            def read(self, size: int = -1) -> bytes:
                return super().read(min(size, 256 * 1024))

        short_read_padding = b"#" + b"x" * (1024 * 1024 + 512) + b"\n"
        short_read_payload = short_read_padding + declaration_payload
        short_read_scan = workspace._stream_secret_scan(
            ShortReadStream(short_read_payload),
            size=len(short_read_payload),
            accepted_values=self.accepted,
        )
        self.assertIsNone(short_read_scan.blocking_rule)
        self.assertEqual(short_read_scan.accepted_counts[accepted], 1)

        source_wrapper = workspace._scan_secret_value(
            b"payload = b'" + exact_assignment + b"'\nstate = 1\n",
            accepted_values=self.accepted,
        )
        self.assertIsNone(source_wrapper.blocking_rule)
        self.assertEqual(source_wrapper.accepted_counts[accepted], 1)

        provider_candidate = b"ghp_" + b"A" * 36
        provider_accepted = accepted_legacy_value(
            provider_candidate.decode("ascii"),
            rule="github-token",
        )
        parenthesized_source_wrapper = workspace._scan_secret_value(
            b"payload = b'access_token = (\""
            + provider_candidate
            + b"\")'\nstate = 1\n",
            accepted_values=(provider_accepted,),
        )
        self.assertIsNone(parenthesized_source_wrapper.blocking_rule)
        self.assertEqual(
            parenthesized_source_wrapper.accepted_counts[provider_accepted],
            1,
        )

        plain_source_wrapper = workspace._scan_secret_value(
            b"payload = '" + exact_assignment + b"'\nstate = 1\n",
            accepted_values=self.accepted,
        )
        self.assertIsNone(plain_source_wrapper.blocking_rule)
        self.assertEqual(plain_source_wrapper.accepted_counts[accepted], 1)

        bounded_source_wrapper = workspace._scan_secret_value(
            b"payload = b'"
            + b"x" * (workspace.MAX_SECRET_ASSIGNMENT_TRAILING_BYTES - 2)
            + exact_assignment
            + b"'\nstate = 1\n",
            accepted_values=self.accepted,
        )
        self.assertIsNone(bounded_source_wrapper.blocking_rule)
        self.assertEqual(bounded_source_wrapper.accepted_counts[accepted], 1)

        oversized_source_wrapper = workspace._scan_secret_value(
            b"payload = b'"
            + b"x" * (workspace.MAX_SECRET_ASSIGNMENT_TRAILING_BYTES - 1)
            + exact_assignment
            + b"'\nstate = 1\n",
            accepted_values=self.accepted,
        )
        self.assertEqual(
            oversized_source_wrapper.blocking_rule,
            "generic-secret-assignment",
        )

        for label, payload in (
            (
                "source-wrapper-literal",
                b"payload = b'"
                + exact_assignment
                + b"' + b'"
                + adjacent_secret
                + b"'\n",
            ),
            (
                "unproven-source-wrapper",
                exact_assignment + b"' + adjacent_secret\n",
            ),
            (
                "mismatched-source-wrapper",
                b"payload = b'" + exact_assignment + b'"\n',
            ),
            (
                "source-wrapper-identifier-continuation",
                b"payload = b'"
                + exact_assignment
                + b"' + suffix + b'"
                + adjacent_secret
                + b"'\n",
            ),
            (
                "source-wrapper-implicit-concatenation",
                b"payload = (b'"
                + exact_assignment
                + b"'\n b'"
                + adjacent_secret
                + b"')\n",
            ),
            (
                "source-wrapper-closed-context-continuation",
                b"payload = ((b'"
                + exact_assignment
                + b"')\n + b'"
                + adjacent_secret
                + b"')\n",
            ),
            (
                "source-wrapper-comparison-continuation",
                b"payload = ((b'"
                + exact_assignment
                + b"')\n not in b'"
                + adjacent_secret
                + b"')\n",
            ),
            (
                "source-wrapper-matrix-continuation",
                b"payload = ((b'"
                + exact_assignment
                + b"')\n @ b'"
                + adjacent_secret
                + b"')\n",
            ),
            (
                "source-wrapper-generator-continuation",
                b"payload = ((b'"
                + exact_assignment
                + b"')\n for item in b'"
                + adjacent_secret
                + b"')\n",
            ),
            (
                "source-wrapper-postfix-continuation",
                b"payload = ((b'"
                + exact_assignment
                + b"')\n [b'"
                + adjacent_secret
                + b"'])\n",
            ),
            (
                "source-wrapper-semicolon-continuation",
                b"payload = b'"
                + exact_assignment
                + b"'; + b'"
                + adjacent_secret
                + b"'\n",
            ),
        ):
            with self.subTest(case=label):
                scan = workspace._scan_secret_value(
                    payload,
                    accepted_values=self.accepted,
                )
                self.assertEqual(
                    scan.blocking_rule,
                    "generic-secret-assignment",
                )

        frozen_diff_boundary = workspace._scan_secret_value(
            b"+check(\n+    scan(b'" + exact_assignment + b"')\n+)\n+state = 1\n",
            accepted_values=self.accepted,
            diff_surface=True,
        )
        self.assertIsNone(frozen_diff_boundary.blocking_rule)
        self.assertEqual(frozen_diff_boundary.accepted_counts[accepted], 1)

        for boundary in (
            b"@@ -10,2 +10,2 @@\n",
            b"diff --git a/next b/next\n",
            b"\\ No newline at end of file\n",
        ):
            with self.subTest(diff_boundary=boundary):
                scan = workspace._scan_secret_value(
                    b"+" + exact_assignment + b"\n" + boundary,
                    accepted_values=self.accepted,
                    diff_surface=True,
                )
                self.assertIsNone(scan.blocking_rule)
                self.assertEqual(scan.accepted_counts[accepted], 1)

                content = workspace._scan_secret_value(
                    b"+" + exact_assignment + b"\n+" + boundary,
                    accepted_values=self.accepted,
                    diff_surface=True,
                )
                self.assertEqual(
                    content.blocking_rule,
                    "generic-secret-assignment",
                )

        lone_cr_metadata = workspace._scan_secret_value(
            b"+" + exact_assignment + b"\r@@ -1 +1 @@ + " + adjacent_secret + b"\n",
            accepted_values=self.accepted,
            diff_surface=True,
        )
        self.assertEqual(
            lone_cr_metadata.blocking_rule,
            "generic-secret-assignment",
        )

        operator_assignment = b'+ state = "' + adjacent_secret + b'"\n'
        for label, payload, diff_surface in (
            (
                "head-operator-assignment",
                exact_assignment + b"\n" + operator_assignment,
                False,
            ),
            (
                "added-operator-assignment",
                b"+" + exact_assignment + b"\n+" + operator_assignment,
                True,
            ),
            (
                "deleted-operator-assignment",
                b"-" + exact_assignment + b"\n-" + operator_assignment,
                True,
            ),
            (
                "context-operator-assignment",
                b" " + exact_assignment + b"\n " + operator_assignment,
                True,
            ),
            (
                "added-comma-operator-assignment",
                b"+configure("
                + exact_assignment
                + b",\n+"
                + operator_assignment
                + b")\n",
                True,
            ),
        ):
            with self.subTest(case=label):
                scan = workspace._scan_secret_value(
                    payload,
                    accepted_values=self.accepted,
                    diff_surface=diff_surface,
                )
                self.assertEqual(
                    scan.blocking_rule,
                    "generic-secret-assignment",
                )

        for fence in (b"```", b"~~~"):
            for label, payload in (
                (
                    "same-line-fence",
                    exact_assignment + b"," + fence + b"\n",
                ),
                (
                    "fence-prefix",
                    exact_assignment
                    + b"\n"
                    + fence
                    + b'python + "'
                    + adjacent_secret
                    + b'"\n',
                ),
            ):
                with self.subTest(case=label, fence=fence):
                    scan = workspace._scan_secret_value(
                        payload,
                        accepted_values=self.accepted,
                    )
                    self.assertEqual(
                        scan.blocking_rule,
                        "generic-secret-assignment",
                    )

        excessive_closers = workspace._scan_secret_value(
            exact_assignment
            + b")" * (workspace.MAX_SECRET_ASSIGNMENT_TRAILING_BYTES + 1),
            accepted_values=self.accepted,
        )
        self.assertEqual(
            excessive_closers.blocking_rule,
            "generic-secret-assignment",
        )

        github_accepted = accepted_legacy_value(GITHUB_LEGACY, rule="github-token")
        github_continuation = workspace._scan_secret_value(
            assignment_bytes(b"access_token", GITHUB_LEGACY.encode("ascii"))
            + b" "
            + adjacent_secret,
            accepted_values=(github_accepted,),
        )
        self.assertEqual(
            github_continuation.blocking_rule,
            "generic-secret-assignment",
        )
        self.assertEqual(github_continuation.accepted_counts[github_accepted], 1)

        first_read = 1024 * 1024
        committed_end = first_read - workspace.STREAM_SCAN_OVERLAP
        for label, trivia in (
            ("space", b" " * (workspace.STREAM_SCAN_OVERLAP + 1)),
            ("newline", b"\n" + b" " * workspace.STREAM_SCAN_OVERLAP),
            ("block-comment", b"/*" + b"x" * workspace.STREAM_SCAN_OVERLAP),
        ):
            with self.subTest(stream_trivia=label):
                long_gap_payload = (
                    b"x" * (committed_end - len(exact_assignment))
                    + exact_assignment
                    + trivia
                    + adjacent_secret
                )
                long_gap = workspace._stream_secret_scan(
                    io.BytesIO(long_gap_payload),
                    size=len(long_gap_payload),
                    accepted_values=self.accepted,
                )
                self.assertEqual(
                    long_gap.blocking_rule,
                    "generic-secret-assignment",
                )

    def test_source_literal_mapping_key_requires_complete_same_side_wrappers(
        self,
    ) -> None:
        accepted = self.accepted[0]
        complete_payload = (
            b'payload = b\'{"OPENAI_API_KEY": "' + accepted.value + b"\"}'\n"
        )
        for label, payload, diff_surface in (
            ("plain", complete_payload, False),
            ("same-side-diff", b"+" + complete_payload, True),
        ):
            with self.subTest(complete=label):
                complete = workspace._scan_secret_value(
                    payload,
                    accepted_values=self.accepted,
                    diff_surface=diff_surface,
                )
                self.assertIsNone(complete.blocking_rule)
                self.assertEqual(complete.accepted_counts[accepted], 1)

        cases = (
            (
                "missing-outer-quote",
                b'payload = b\'{"OPENAI_API_KEY": "' + accepted.value + b'"}\n',
                False,
            ),
            (
                "missing-logical-object-closer",
                b'payload = b\'{"OPENAI_API_KEY": "' + accepted.value + b"\"'\n",
                False,
            ),
            (
                "escaped-mapping-key-opener",
                b"payload = b'{"
                + b'\\"OPENAI_API_KEY": "'
                + accepted.value
                + b"\"}'\n",
                False,
            ),
            (
                "opposite-side-wrapper-closers",
                b'+payload = b\'{"OPENAI_API_KEY": "' + accepted.value + b"\"\n-}'\n",
                True,
            ),
        )
        for label, payload, diff_surface in cases:
            with self.subTest(case=label):
                scan = workspace._scan_secret_value(
                    payload,
                    accepted_values=self.accepted,
                    diff_surface=diff_surface,
                )
                self.assertEqual(
                    scan.blocking_rule,
                    "generic-secret-assignment",
                )
                self.assertEqual(scan.accepted_counts[accepted], 0)

    def test_diff_quoted_assignment_respects_record_side(self) -> None:
        accepted = self.accepted[0]
        quoted_mapping = b'        "OPENAI_API_KEY": "' + accepted.value + b'",\n'
        long_replacement = b"        replacement(" + b"argument, " * 40 + b")\n"
        self.assertGreater(
            len(long_replacement),
            workspace.MAX_SECRET_ASSIGNMENT_TRAILING_BYTES,
        )

        for label, payload in (
            (
                "base-assignment-with-head-replacement",
                b"-" + quoted_mapping + b"+" + long_replacement,
            ),
            (
                "head-assignment-with-base-replacement",
                b"+" + quoted_mapping + b"-" + long_replacement,
            ),
            (
                "base-assignment-with-triple-plus-replacement",
                b"-" + quoted_mapping + b"+++ replacement\n",
            ),
            (
                "head-assignment-with-triple-minus-replacement",
                b"+" + quoted_mapping + b"--- replacement\n",
            ),
            (
                "base-assignment-with-next-base-field",
                b"-"
                + quoted_mapping
                + b"+"
                + long_replacement
                + b'-        "state": "expired",\n',
            ),
            (
                "base-assignment-with-next-context-field",
                b"-"
                + quoted_mapping
                + b"+"
                + long_replacement
                + b'         "state": "expired",\n',
            ),
        ):
            with self.subTest(accepted=label):
                scan = workspace._scan_secret_value(
                    payload,
                    accepted_values=self.accepted,
                    diff_surface=True,
                )
                self.assertIsNone(scan.blocking_rule)
                self.assertEqual(scan.accepted_counts[accepted], 1)

        declaration_assignment = b'OPENAI_API_KEY = "' + accepted.value + b'",\n'
        for label, hunk_header, opposite_record, source_side in (
            (
                "base-prefix-after-triple-plus",
                b"@@ -1,3 +1,1 @@\n",
                b"+++ replacement\n",
                b"-",
            ),
            (
                "head-prefix-after-triple-minus",
                b"@@ -1,1 +1,3 @@\n",
                b"--- replacement\n",
                b"+",
            ),
        ):
            with self.subTest(accepted=label):
                scan = workspace._scan_secret_value(
                    b"diff --git a/fixture.py b/fixture.py\n"
                    b"--- a/fixture.py\n"
                    b"+++ b/fixture.py\n"
                    + hunk_header
                    + opposite_record
                    + source_side
                    + declaration_assignment
                    + source_side
                    + b"def test_fixture():\n"
                    + source_side
                    + b"    pass\n",
                    accepted_values=self.accepted,
                    diff_surface=True,
                )
                self.assertIsNone(scan.blocking_rule)
                self.assertEqual(scan.accepted_counts[accepted], 1)

        triple_assignment = b'OPENAI_API_KEY = "' + accepted.value + b'",\n'
        for label, record_prefix, opposite_side in (
            ("triple-plus-matched-record", b"+++ ", b"-"),
            ("triple-minus-matched-record", b"--- ", b"+"),
        ):
            with self.subTest(accepted=label):
                scan = workspace._scan_secret_value(
                    b"diff --git a/fixture.py b/fixture.py\n"
                    b"--- a/fixture.py\n"
                    b"+++ b/fixture.py\n"
                    b"@@ -1 +1 @@\n"
                    + record_prefix
                    + triple_assignment
                    + opposite_side
                    + long_replacement,
                    accepted_values=self.accepted,
                    diff_surface=True,
                )
                self.assertIsNone(scan.blocking_rule)
                self.assertEqual(scan.accepted_counts[accepted], 1)

        actual_file_header = workspace._scan_secret_value(
            b"diff --git a/fixture.py b/fixture.py\n"
            b"--- a/fixture.py\n"
            b'+++ OPENAI_API_KEY = "' + accepted.value + b'",\n' + b"@@ -1 +1 @@\n",
            accepted_values=self.accepted,
            diff_surface=True,
        )
        self.assertEqual(
            actual_file_header.blocking_rule,
            "generic-secret-assignment",
        )

        incomplete_prefix_hunk = workspace._scan_secret_value(
            b"@@ -1 +1 @@\n+++ " + triple_assignment + b"-" + long_replacement,
            accepted_values=self.accepted,
            diff_surface=True,
            prefix_context_complete=False,
        )
        self.assertEqual(
            incomplete_prefix_hunk.blocking_rule,
            "generic-secret-assignment",
        )

        with mock.patch.object(
            workspace,
            "MAX_SECRET_PREFIX_PROOF_BYTES",
            64,
        ):
            out_of_range_hunk = workspace._scan_secret_value(
                b"@@ -1 +1 @@\n" + b" " + b"x" * 128 + b"\n+++ " + triple_assignment,
                accepted_values=self.accepted,
                diff_surface=True,
            )
        self.assertEqual(
            out_of_range_hunk.blocking_rule,
            "generic-secret-assignment",
        )

        exhausted_hunk_budget = workspace.SecretScanBudget(
            workspace.MAX_SECRET_SCAN_EVENTS,
            remaining_prefix_proof_bytes=0,
        )
        with self.assertRaisesRegex(ReviewError, "prefix proof limit"):
            workspace._scan_secret_value(
                b"diff --git a/fixture.py b/fixture.py\n"
                b"--- a/fixture.py\n"
                b"+++ b/fixture.py\n"
                b"@@ -1 +1 @@\n"
                b"+++ " + triple_assignment + b"-" + long_replacement,
                accepted_values=self.accepted,
                diff_surface=True,
                _event_budget=exhausted_hunk_budget,
            )

        stale_hunk_before_file_header = workspace._scan_secret_value(
            b"@@ -1 +1 @@\n"
            b" context\n"
            b"diff --git a/fixture.py b/fixture.py\n"
            b'--- OPENAI_API_KEY = "'
            + accepted.value
            + b'",\n'
            + b"+++ "
            + long_replacement
            + b"@@ -1 +1 @@\n",
            accepted_values=self.accepted,
            diff_surface=True,
        )
        self.assertEqual(
            stale_hunk_before_file_header.blocking_rule,
            "generic-secret-assignment",
        )

        proof_bytes = 4096
        # Leave enough of the absolute assignment proof window for the next
        # source-side declaration that terminates this diff assignment.
        opposite_record_bytes = proof_bytes // 2
        long_opposite_record = b"+" + b"x" * (opposite_record_bytes - 2) + b"\n"
        long_opposite_payload = (
            b"@@ -1,3 +1,1 @@\n"
            b"-" + triple_assignment + long_opposite_record + b"-def test_fixture():\n"
            b"-    pass\n"
        )
        exact_proof_budget = (
            len(long_opposite_record) + len(b"-" + triple_assignment) + 1
        )
        long_opposite_budget = workspace.SecretScanBudget(
            workspace.MAX_SECRET_SCAN_EVENTS,
            remaining_prefix_proof_bytes=exact_proof_budget,
        )
        with mock.patch.object(
            workspace,
            "MAX_SECRET_PREFIX_PROOF_BYTES",
            proof_bytes,
        ):
            long_opposite_prefix = workspace._scan_secret_value(
                long_opposite_payload,
                accepted_values=self.accepted,
                diff_surface=True,
                _event_budget=long_opposite_budget,
            )
            with self.assertRaisesRegex(ReviewError, "prefix proof limit"):
                workspace._scan_secret_value(
                    long_opposite_payload,
                    accepted_values=self.accepted,
                    diff_surface=True,
                    _event_budget=workspace.SecretScanBudget(
                        workspace.MAX_SECRET_SCAN_EVENTS,
                        remaining_prefix_proof_bytes=exact_proof_budget - 1,
                    ),
                )
        self.assertIsNone(long_opposite_prefix.blocking_rule)
        self.assertEqual(
            long_opposite_prefix.accepted_counts[accepted],
            1,
        )
        self.assertEqual(
            long_opposite_budget.remaining_prefix_proof_bytes,
            0,
        )

        streamed_hunk_payload = (
            b"@@ -1,3 +1,1 @@\n"
            b" #"
            + b"x" * 3900
            + b"\n-"
            + triple_assignment
            + b"+replacement("
            + b"x" * 800
            + b")\n-def test_fixture():\n"
            b"-    pass\n"
        )
        late_assignment_start = proof_bytes + 256 + 64
        late_hunk_prefix = b"x" * (proof_bytes - 700) + b"\n@@ -1,4 +1,1 @@\n"
        late_comment_size = late_assignment_start - len(late_hunk_prefix)
        late_streamed_hunk_payload = (
            late_hunk_prefix
            + b"-#"
            + b"x" * (late_comment_size - 3)
            + b"\n-"
            + triple_assignment
            + b"+replacement("
            + b"x" * 1500
            + b")\n-def test_fixture():\n"
            b"-    pass\n"
        )
        stale_file_prefix = (
            b"x" * (proof_bytes - 700)
            + b"\n@@ -1,4 +1,1 @@\n"
            + b"diff --git a/next.py b/next.py\n"
        )
        stale_comment_size = late_assignment_start - len(stale_file_prefix)
        stale_streamed_hunk_payload = (
            stale_file_prefix
            + b"-#"
            + b"x" * (stale_comment_size - 3)
            + b"\n-"
            + triple_assignment
            + b"+replacement("
            + b"x" * 1500
            + b")\n-def test_fixture():\n"
            b"-    pass\n"
        )
        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", 256),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 1024),
        ):
            direct_hunk_scan = workspace._scan_secret_value(
                streamed_hunk_payload,
                accepted_values=self.accepted,
                diff_surface=True,
            )
            streamed_hunk_scan = workspace._stream_secret_scan(
                io.BytesIO(streamed_hunk_payload),
                size=len(streamed_hunk_payload),
                accepted_values=self.accepted,
                diff_surface=True,
            )
            late_direct_hunk_scan = workspace._scan_secret_value(
                late_streamed_hunk_payload,
                accepted_values=self.accepted,
                diff_surface=True,
            )
            late_streamed_hunk_scan = workspace._stream_secret_scan(
                io.BytesIO(late_streamed_hunk_payload),
                size=len(late_streamed_hunk_payload),
                accepted_values=self.accepted,
                diff_surface=True,
            )
            stale_direct_hunk_scan = workspace._scan_secret_value(
                stale_streamed_hunk_payload,
                accepted_values=self.accepted,
                diff_surface=True,
            )
            stale_streamed_hunk_scan = workspace._stream_secret_scan(
                io.BytesIO(stale_streamed_hunk_payload),
                size=len(stale_streamed_hunk_payload),
                accepted_values=self.accepted,
                diff_surface=True,
            )
        self.assertIsNone(direct_hunk_scan.blocking_rule)
        self.assertEqual(direct_hunk_scan.accepted_counts[accepted], 1)
        self.assertIsNone(streamed_hunk_scan.blocking_rule)
        self.assertEqual(streamed_hunk_scan.accepted_counts[accepted], 1)
        self.assertIsNone(late_direct_hunk_scan.blocking_rule)
        self.assertEqual(late_direct_hunk_scan.accepted_counts[accepted], 1)
        self.assertIsNone(late_streamed_hunk_scan.blocking_rule)
        self.assertEqual(late_streamed_hunk_scan.accepted_counts[accepted], 1)
        self.assertEqual(
            stale_direct_hunk_scan.blocking_rule,
            "generic-secret-assignment",
        )
        self.assertEqual(
            stale_streamed_hunk_scan.blocking_rule,
            "generic-secret-assignment",
        )

        for hunk_label, hunk_header in (
            ("ordinary", b"@@ -1,3 +1,1 @@\n"),
            ("combined", b"@@@ -1,3 -1,3 +1,1 @@@\n"),
        ):
            for side_label, record_prefix, opposite_side in (
                ("head", b"+++ ", b"-"),
                ("base", b"--- ", b"+"),
            ):
                with self.subTest(
                    retained_hunk=hunk_label,
                    retained_side=side_label,
                ):
                    retained_triple_payload = (
                        hunk_header
                        + b" #"
                        + b"x" * 3900
                        + b"\n"
                        + record_prefix
                        + triple_assignment
                        + opposite_side
                        + b"replacement("
                        + b"x" * 800
                        + b")\n"
                    )
                    with (
                        mock.patch.object(
                            workspace,
                            "MAX_SECRET_PREFIX_PROOF_BYTES",
                            proof_bytes,
                        ),
                        mock.patch.object(
                            workspace,
                            "STREAM_SCAN_OVERLAP",
                            256,
                        ),
                        mock.patch.object(
                            workspace,
                            "STREAM_SCAN_CHUNK_BYTES",
                            1024,
                        ),
                    ):
                        retained_triple_direct = workspace._scan_secret_value(
                            retained_triple_payload,
                            accepted_values=self.accepted,
                            diff_surface=True,
                        )
                        retained_triple_stream = workspace._stream_secret_scan(
                            io.BytesIO(retained_triple_payload),
                            size=len(retained_triple_payload),
                            accepted_values=self.accepted,
                            diff_surface=True,
                        )
                    self.assertIsNone(retained_triple_direct.blocking_rule)
                    self.assertEqual(
                        retained_triple_direct.accepted_counts[accepted],
                        1,
                    )
                    self.assertEqual(
                        retained_triple_stream,
                        retained_triple_direct,
                    )

        for file_prefix in (b"+++ ", b"--- "):
            actual_header_payload = (
                b"diff --git a/fixture.py b/fixture.py\n"
                + file_prefix
                + triple_assignment
            )
            actual_header_direct = workspace._scan_secret_value(
                actual_header_payload,
                accepted_values=self.accepted,
                diff_surface=True,
            )
            actual_header_stream = workspace._stream_secret_scan(
                io.BytesIO(actual_header_payload),
                size=len(actual_header_payload),
                accepted_values=self.accepted,
                diff_surface=True,
            )
            self.assertEqual(
                actual_header_direct.blocking_rule,
                "generic-secret-assignment",
            )
            self.assertEqual(actual_header_stream, actual_header_direct)

        retention_lookbehind = proof_bytes + 256
        for hunk_header in (
            b"@@ -1,3 +1,1 @@\n",
            b"@@@ -1,3 -1,3 +1,1 @@@\n",
        ):
            boundary_value = hunk_header + b"x" * (
                retention_lookbehind + 1 - len(hunk_header)
            )
            exact_context, exact_lower = workspace._bounded_diff_hunk_context_before(
                boundary_value,
                retention_lookbehind,
                prefix_context_complete=True,
                lookbehind_bytes=retention_lookbehind,
            )
            over_context, over_lower = workspace._bounded_diff_hunk_context_before(
                boundary_value,
                retention_lookbehind + 1,
                prefix_context_complete=True,
                lookbehind_bytes=retention_lookbehind,
            )
            self.assertIsNotNone(exact_context)
            self.assertEqual(exact_lower, 0)
            self.assertIsNone(over_context)
            self.assertEqual(over_lower, 1)

        adjacent_secret = b'"ActualOpaque' + b'SecretA9Z8Y7"'
        for label, continuation in (
            ("context", b"     + " + adjacent_secret + b"\n"),
            ("same-side", b"-    + " + adjacent_secret + b"\n"),
        ):
            with self.subTest(blocked_continuation=label):
                scan = workspace._scan_secret_value(
                    b"-" + quoted_mapping + b"+replacement()\n" + continuation,
                    accepted_values=self.accepted,
                    diff_surface=True,
                )
                self.assertEqual(
                    scan.blocking_rule,
                    "generic-secret-assignment",
                )

        incomplete_base_prefix = workspace._scan_secret_value(
            b"@@ -1,3 +1,1 @@\n"
            b"-configure(\n"
            b"-" + quoted_mapping + b"+replacement()\n"
            b"-def test_fixture():\n"
            b"-    pass\n",
            accepted_values=self.accepted,
            diff_surface=True,
        )
        self.assertEqual(
            incomplete_base_prefix.blocking_rule,
            "generic-secret-assignment",
        )

        exhausted_budget = workspace.SecretScanBudget(
            workspace.MAX_SECRET_SCAN_EVENTS,
            remaining_prefix_proof_bytes=0,
        )
        with self.assertRaisesRegex(ReviewError, "prefix proof limit"):
            workspace._scan_secret_value(
                b"-" + quoted_mapping + b"+" + long_replacement,
                accepted_values=self.accepted,
                diff_surface=True,
                _event_budget=exhausted_budget,
            )

        with mock.patch.object(
            workspace,
            "MAX_SECRET_PREFIX_PROOF_BYTES",
            len(long_replacement) - 1,
        ):
            oversized_opposite_record = workspace._scan_secret_value(
                b"-" + quoted_mapping + b"+" + long_replacement,
                accepted_values=self.accepted,
                diff_surface=True,
            )
        self.assertEqual(
            oversized_opposite_record.blocking_rule,
            "generic-secret-assignment",
        )

    @mock.patch.object(workspace, "MAX_SECRET_PREFIX_PROOF_BYTES", 8192)
    @mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", 256)
    @mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 1024)
    def test_diff_opposite_record_continuation_survives_stream_boundary(
        self,
    ) -> None:
        accepted = self.accepted[0]
        quoted_assignment = b'-OPENAI_API_KEY = "' + accepted.value + b'",\n'
        padding_size = workspace.MAX_SECRET_PREFIX_PROOF_BYTES - 1024
        padding = b" " + b"x" * padding_size + b"\n"
        opposite_record = (
            b"+replacement(" + b"x" * (workspace.STREAM_SCAN_OVERLAP + 4096) + b")\n"
        )
        adjacent_secret = b'"ActualOpaque' + b'SecretA9Z8Y7"'
        payload = (
            padding
            + quoted_assignment
            + opposite_record
            + b"     + "
            + adjacent_secret
            + b"\n"
        )

        scan = workspace._stream_secret_scan(
            io.BytesIO(payload),
            size=len(payload),
            accepted_values=self.accepted,
            diff_surface=True,
        )

        self.assertEqual(
            scan.blocking_rule,
            "generic-secret-assignment",
        )

        first_read_size = (
            workspace.MAX_SECRET_PREFIX_PROOF_BYTES + workspace.STREAM_SCAN_OVERLAP
        )
        boundary_prefix = padding + quoted_assignment
        boundary_opposite = (
            b"+" + b"x" * (first_read_size - len(boundary_prefix) - 2) + b"\n"
        )
        boundary_payload = (
            boundary_prefix + boundary_opposite + b"     + " + adjacent_secret + b"\n"
        )
        boundary_scan = workspace._stream_secret_scan(
            io.BytesIO(boundary_payload),
            size=len(boundary_payload),
            accepted_values=self.accepted,
            diff_surface=True,
        )
        self.assertEqual(
            boundary_scan.blocking_rule,
            "generic-secret-assignment",
        )

        head_boundary_prefix = padding + b"+" + quoted_assignment[1:]
        for label, case_prefix, opposite_side, partial_record in (
            ("base-marker", boundary_prefix, b"+", b"-"),
            ("base-indented", boundary_prefix, b"+", b"-    "),
            ("context-marker", boundary_prefix, b"+", b" "),
            ("context-indented", boundary_prefix, b"+", b"     "),
            ("head-marker", head_boundary_prefix, b"-", b"+"),
            ("head-indented", head_boundary_prefix, b"-", b"+    "),
        ):
            with self.subTest(partial_record=label):
                partial_opposite = (
                    opposite_side
                    + b"x"
                    * (first_read_size - len(case_prefix) - len(partial_record) - 2)
                    + b"\n"
                )
                partial_chunk = case_prefix + partial_opposite + partial_record
                partial_payload = partial_chunk + b"+ " + adjacent_secret + b"\n"
                direct_scan = workspace._scan_secret_value(
                    partial_chunk,
                    accepted_values=self.accepted,
                    diff_surface=True,
                    suffix_context_complete=False,
                )
                self.assertIsNotNone(direct_scan.incomplete_suffix_start)
                full_scan = workspace._scan_secret_value(
                    partial_payload,
                    accepted_values=self.accepted,
                    diff_surface=True,
                )
                self.assertEqual(
                    full_scan.blocking_rule,
                    "generic-secret-assignment",
                )
                partial_scan = workspace._stream_secret_scan(
                    io.BytesIO(partial_payload),
                    size=len(partial_payload),
                    accepted_values=self.accepted,
                    diff_surface=True,
                )
                self.assertEqual(
                    partial_scan.blocking_rule,
                    "generic-secret-assignment",
                )

        safe_payload = padding + quoted_assignment + opposite_record.removesuffix(b"\n")
        safe_scan = workspace._stream_secret_scan(
            io.BytesIO(safe_payload),
            size=len(safe_payload),
            accepted_values=self.accepted,
            diff_surface=True,
        )
        self.assertIsNone(safe_scan.blocking_rule)
        self.assertEqual(safe_scan.accepted_counts[accepted], 1)

        safe_complete_payload = boundary_prefix + b"+replacement()\n"
        safe_complete_scan = workspace._stream_secret_scan(
            io.BytesIO(safe_complete_payload),
            size=len(safe_complete_payload),
            accepted_values=self.accepted,
            diff_surface=True,
        )
        self.assertIsNone(safe_complete_scan.blocking_rule)
        self.assertEqual(safe_complete_scan.accepted_counts[accepted], 1)

        safe_partial_payload = boundary_prefix + b"+replacement()\n-    "
        safe_partial_scan = workspace._stream_secret_scan(
            io.BytesIO(safe_partial_payload),
            size=len(safe_partial_payload),
            accepted_values=self.accepted,
            diff_surface=True,
        )
        self.assertIsNone(safe_partial_scan.blocking_rule)
        self.assertEqual(safe_partial_scan.accepted_counts[accepted], 1)

        safe_head_partial_payload = head_boundary_prefix + b"-replacement()\n+    "
        safe_head_partial_scan = workspace._stream_secret_scan(
            io.BytesIO(safe_head_partial_payload),
            size=len(safe_head_partial_payload),
            accepted_values=self.accepted,
            diff_surface=True,
        )
        self.assertIsNone(safe_head_partial_scan.blocking_rule)
        self.assertEqual(safe_head_partial_scan.accepted_counts[accepted], 1)

    def test_diff_incomplete_suffix_commits_each_complete_prefix(self) -> None:
        accepted = self.accepted[0]
        proof_bytes = 16 * 1024
        overlap = 256
        first_read_size = proof_bytes + overlap
        assignment = b'-OPENAI_API_KEY = "' + accepted.value + b'",\n'
        opposite_start = b"+replacement("
        assignment_count = 8
        hunk_header = f"@@ -1,{assignment_count} +1,{assignment_count} @@\n".encode(
            "ascii"
        )
        padding_size = proof_bytes - len(hunk_header) - len(assignment) - 64
        padding = b" " + b"x" * (padding_size - 2) + b"\n"
        first_prefix = padding + hunk_header + assignment + opposite_start
        segments = [first_prefix + b"x" * (first_read_size - len(first_prefix))]
        for _index in range(assignment_count - 1):
            next_prefix = b"x" * 64 + b")\n" + assignment + opposite_start
            segments.append(next_prefix + b"x" * (1024 - len(next_prefix)))
        segments.append(b"x" * 64 + b")\n")

        class SegmentedStream:
            def __init__(self, chunks: list[bytes]) -> None:
                self.chunks = list(chunks)

            def read(self, size: int = -1) -> bytes:
                if not self.chunks:
                    return b""
                chunk = self.chunks.pop(0)
                if size >= 0 and len(chunk) > size:
                    raise AssertionError("test segment exceeds requested read size")
                return chunk

        pending_lengths: list[int] = []
        scan_calls: list[tuple[bytes, int, int | None, int | None]] = []
        original_scan = workspace._scan_secret_value

        def recording_scan(value: bytes, **kwargs):
            pending_lengths.append(len(value))
            result = original_scan(value, **kwargs)
            scan_calls.append(
                (
                    value,
                    kwargs.get("minimum_end", 0),
                    kwargs.get("maximum_end"),
                    result.incomplete_suffix_start,
                )
            )
            return result

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 1024),
            mock.patch.object(
                workspace,
                "_scan_secret_value",
                side_effect=recording_scan,
            ),
        ):
            scan = workspace._stream_secret_scan(
                SegmentedStream(segments),
                accepted_values=self.accepted,
                diff_surface=True,
            )

        self.assertIsNone(scan.blocking_rule)
        self.assertEqual(scan.accepted_counts[accepted], assignment_count)
        self.assertTrue(pending_lengths)
        self.assertLessEqual(max(pending_lengths), first_read_size)
        incomplete_calls = [
            (index, value, minimum_end, incomplete_start)
            for index, (
                value,
                minimum_end,
                _maximum_end,
                incomplete_start,
            ) in enumerate(scan_calls)
            if incomplete_start is not None
        ]
        self.assertEqual(len(incomplete_calls), assignment_count)
        incomplete_minimums = [
            minimum_end
            for _index, _value, minimum_end, _incomplete_start in incomplete_calls
        ]
        self.assertEqual(incomplete_minimums, sorted(incomplete_minimums))
        self.assertEqual(len(set(incomplete_minimums)), assignment_count)
        for index, value, minimum_end, incomplete_start in incomplete_calls:
            self.assertIsNotNone(
                workspace.QUOTED_SECRET_ASSIGNMENT.match(value, incomplete_start)
            )
            replay_value, replay_minimum, replay_maximum, replay_incomplete = (
                scan_calls[index + 1]
            )
            self.assertEqual(replay_value, value)
            self.assertEqual(replay_minimum, minimum_end)
            self.assertEqual(replay_maximum, incomplete_start)
            self.assertIsNone(replay_incomplete)

        pem_proof_bytes = 4096
        pem_overlap = 256
        pem_first_read = pem_proof_bytes + pem_overlap
        pem_assignment = b'-OPENAI_API_KEY = "' + accepted.value + b'",\n'
        pem_begin = b"------BEGIN " + b"PRIVATE KEY-----\n"
        pem_begin_line_start = pem_proof_bytes - pem_overlap - 512
        pem_assignment_line_start = pem_proof_bytes - 128
        pem_padding = b" " + b"x" * (pem_begin_line_start - 2) + b"\n"
        pem_gap_size = pem_assignment_line_start - pem_begin_line_start - len(pem_begin)
        pem_gap = b"-" + b"A" * (pem_gap_size - 2) + b"\n"
        pem_prefix = pem_padding + pem_begin + pem_gap + pem_assignment
        pem_opposite_start = b"+replacement("
        pem_first_chunk = (
            pem_prefix
            + pem_opposite_start
            + b"x" * (pem_first_read - len(pem_prefix) - len(pem_opposite_start))
        )
        pem_second_chunk = b"x" * 64 + b")\n+-----END " + b"PRIVATE KEY-----\n"
        pem_payload = pem_first_chunk + pem_second_chunk
        pem_begin_match = workspace.PEM_PRIVATE_KEY_BEGIN.search(pem_first_chunk)
        pem_assignment_match = workspace.QUOTED_SECRET_ASSIGNMENT.search(
            pem_first_chunk
        )
        self.assertIsNotNone(pem_begin_match)
        self.assertIsNotNone(pem_assignment_match)
        self.assertEqual(len(pem_first_chunk), pem_first_read)
        self.assertLessEqual(pem_assignment_match.end(), pem_proof_bytes)
        self.assertGreater(
            pem_assignment_match.start() - pem_begin_match.start(),
            pem_overlap,
        )

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                pem_proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", pem_overlap),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 1024),
        ):
            pem_direct = workspace._scan_secret_value(
                pem_payload,
                accepted_values=self.accepted,
                diff_surface=True,
            )
            pem_stream = workspace._stream_secret_scan(
                io.BytesIO(pem_payload),
                size=len(pem_payload),
                accepted_values=self.accepted,
                diff_surface=True,
            )

        self.assertEqual(pem_direct.blocking_rule, "private-key")
        self.assertEqual(pem_stream.blocking_rule, "private-key")

    def test_diff_incomplete_suffix_does_not_recharge_deferred_match(
        self,
    ) -> None:
        accepted = self.accepted[0]
        proof_bytes = 4096
        overlap = 256
        first_read_size = proof_bytes + overlap
        assignment = b'-OPENAI_API_KEY = "' + accepted.value + b'",\n'
        opposite_start = b"+replacement("
        padding_size = proof_bytes - len(assignment) - 64
        padding = b" " + b"x" * (padding_size - 2) + b"\n"
        first_prefix = padding + assignment + opposite_start
        segments = [
            first_prefix + b"x" * (first_read_size - len(first_prefix)),
            b"x" * 64 + b")\n",
        ]

        class SegmentedStream:
            def __init__(self, chunks: list[bytes]) -> None:
                self.chunks = list(chunks)

            def read(self, size: int = -1) -> bytes:
                if not self.chunks:
                    return b""
                chunk = self.chunks.pop(0)
                if size >= 0 and len(chunk) > size:
                    raise AssertionError("test segment exceeds requested read size")
                return chunk

        budget = workspace.SecretScanBudget(
            workspace.MAX_SECRET_SCAN_EVENTS,
            remaining_prefix_proof_bytes=proof_bytes + 1200,
        )
        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(
                workspace.SecretScanBudget,
                "default",
                return_value=budget,
            ),
        ):
            scan = workspace._stream_secret_scan(
                SegmentedStream(segments),
                accepted_values=self.accepted,
                diff_surface=True,
            )

        self.assertIsNone(scan.blocking_rule)
        self.assertEqual(scan.accepted_counts[accepted], 1)

    def test_diff_incomplete_suffix_does_not_recharge_committed_events(
        self,
    ) -> None:
        accepted = self.accepted[0]
        proof_bytes = 4096
        overlap = 256
        first_read_size = proof_bytes + overlap
        safe_assignments = (
            b"-access_token = "
            + accepted.value
            + b"\n-access_token = "
            + accepted.value
            + b"\n"
        )
        deferred_assignment = b'-OPENAI_API_KEY = "' + accepted.value + b'",\n'
        opposite_start = b"+replacement("
        padding_size = (
            proof_bytes - len(safe_assignments) - len(deferred_assignment) - 64
        )
        first_prefix = (
            b" "
            + b"x" * (padding_size - 2)
            + b"\n"
            + safe_assignments
            + deferred_assignment
            + opposite_start
        )
        first_chunk = first_prefix + b"x" * (first_read_size - len(first_prefix))
        payload = first_chunk + b"x" * 64 + b")\n"
        budget = workspace.SecretScanBudget(3)

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(
                workspace.SecretScanBudget,
                "default",
                return_value=budget,
            ),
        ):
            scan = workspace._stream_secret_scan(
                io.BytesIO(payload),
                size=len(payload),
                accepted_values=self.accepted,
                diff_surface=True,
            )

        self.assertIsNone(scan.blocking_rule)
        self.assertEqual(scan.accepted_counts[accepted], 3)
        self.assertEqual(budget.remaining, 0)

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(
                workspace.SecretScanBudget,
                "default",
                return_value=workspace.SecretScanBudget(2),
            ),
            self.assertRaisesRegex(ReviewError, "scanner event limit"),
        ):
            workspace._stream_secret_scan(
                io.BytesIO(payload),
                size=len(payload),
                accepted_values=self.accepted,
                diff_surface=True,
            )

    def test_diff_incomplete_suffix_commits_prefix_proof_once(self) -> None:
        accepted = self.accepted[0]
        proof_bytes = 4096
        overlap = 256
        assignment = b'-OPENAI_API_KEY = "' + accepted.value + b'",\n'
        opposite_record = b"+replacement(" + b"x" * 512 + b")\n"
        padding_size = proof_bytes - len(assignment) - 64
        payload = (
            b" " + b"x" * (padding_size - 2) + b"\n" + assignment + opposite_record
        )
        assignment_match = workspace.QUOTED_SECRET_ASSIGNMENT.search(payload)
        self.assertIsNotNone(assignment_match)
        exact_proof_budget = assignment_match.start() + len(opposite_record)
        direct_budget = workspace.SecretScanBudget(
            1,
            remaining_prefix_proof_bytes=exact_proof_budget,
        )
        bytesio_budget = workspace.SecretScanBudget(
            1,
            remaining_prefix_proof_bytes=exact_proof_budget,
        )
        short_read_budget = workspace.SecretScanBudget(
            1,
            remaining_prefix_proof_bytes=exact_proof_budget,
        )

        class OneByteReadStream(io.BytesIO):
            def __init__(self, value: bytes) -> None:
                super().__init__(value)
                self.read_calls = 0

            def read(self, size: int = -1) -> bytes:
                self.read_calls += 1
                return super().read(min(size, 1))

        short_read_stream = OneByteReadStream(payload)

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
        ):
            direct_scan = workspace._scan_secret_value(
                payload,
                accepted_values=self.accepted,
                diff_surface=True,
                _event_budget=direct_budget,
            )

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(
                workspace.SecretScanBudget,
                "default",
                return_value=bytesio_budget,
            ),
        ):
            bytesio_scan = workspace._stream_secret_scan(
                io.BytesIO(payload),
                size=len(payload),
                accepted_values=self.accepted,
                diff_surface=True,
            )

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(
                workspace.SecretScanBudget,
                "default",
                return_value=short_read_budget,
            ),
            mock.patch.object(
                workspace,
                "_scan_secret_value",
                wraps=workspace._scan_secret_value,
            ) as scan_spy,
        ):
            short_read_scan = workspace._stream_secret_scan(
                short_read_stream,
                size=len(payload),
                accepted_values=self.accepted,
                diff_surface=True,
            )

        self.assertEqual(bytesio_scan, direct_scan)
        self.assertEqual(short_read_scan, direct_scan)
        self.assertIsNone(direct_scan.blocking_rule)
        self.assertEqual(direct_scan.accepted_counts[accepted], 1)
        self.assertEqual(
            {
                (
                    budget.remaining,
                    budget.remaining_prefix_proof_bytes,
                )
                for budget in (
                    direct_budget,
                    bytesio_budget,
                    short_read_budget,
                )
            },
            {(0, 0)},
        )
        self.assertGreater(short_read_stream.read_calls, scan_spy.call_count)
        self.assertEqual(scan_spy.call_count, 3)

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(
                workspace.SecretScanBudget,
                "default",
                return_value=workspace.SecretScanBudget(
                    workspace.MAX_SECRET_SCAN_EVENTS,
                    remaining_prefix_proof_bytes=exact_proof_budget - 1,
                ),
            ),
            self.assertRaisesRegex(ReviewError, "prefix proof limit"),
        ):
            workspace._stream_secret_scan(
                io.BytesIO(payload),
                size=len(payload),
                accepted_values=self.accepted,
                diff_surface=True,
            )

    def test_diff_source_proof_watermark_preserves_per_assignment_limit(
        self,
    ) -> None:
        accepted = self.accepted[0]
        payload = (
            b"@@ -1,3 +1,1 @@\n"
            b"-#"
            + b"x" * 12
            + b"\n"
            + b'-OPENAI_API_KEY = "'
            + accepted.value
            + b'",\n'
            + b"-def test_fixture():\n"
            + b"-    pass\n"
        )
        budget = workspace.SecretScanBudget(
            workspace.MAX_SECRET_SCAN_EVENTS,
            remaining_prefix_proof_bytes=workspace.MAX_SECRET_PREFIX_PROOF_TOTAL_BYTES,
        )

        with mock.patch.object(
            workspace,
            "MAX_SECRET_PREFIX_PROOF_BYTES",
            64,
        ):
            scan = workspace._scan_secret_value(
                payload,
                accepted_values=self.accepted,
                diff_surface=True,
                _event_budget=budget,
            )

        self.assertEqual(scan.blocking_rule, "generic-secret-assignment")
        self.assertEqual(scan.accepted_counts[accepted], 0)

    def test_stream_scan_rejects_invalid_known_size(self) -> None:
        with self.assertRaisesRegex(ReviewError, "size must be nonnegative"):
            workspace._stream_secret_scan(io.BytesIO(b""), size=-1)

        with self.assertRaisesRegex(ReviewError, "unexpected end"):
            workspace._stream_secret_scan(io.BytesIO(b""), size=1)

        class OversizedReadStream:
            def read(self, _size: int = -1) -> bytes:
                return b"xx"

        with self.assertRaisesRegex(ReviewError, "more bytes than requested"):
            workspace._stream_secret_scan(OversizedReadStream(), size=1)

    def test_dense_accepted_surface_fails_closed_at_the_event_limit(self) -> None:
        accepted = self.accepted[0]
        for label, value in (
            ("accepted", accepted.value),
            ("placeholder", b"placeholder_token"),
        ):
            with self.subTest(case=label):
                payload = b"\n".join(
                    assignment_bytes(b"access_token", value) for _ in range(3)
                )
                with (
                    mock.patch.object(workspace, "MAX_SECRET_SCAN_EVENTS", 2),
                    self.assertRaisesRegex(ReviewError, "scanner event limit"),
                ):
                    workspace._scan_secret_value(
                        payload,
                        accepted_values=self.accepted,
                    )

    def test_blocking_event_stops_scanning_the_remaining_surface(self) -> None:
        budget = workspace.SecretScanBudget(1)
        payload = (
            assignment_bytes(b"access_token", b"UnknownSecretValueA9Z8Y7")
            + b"\n"
            + assignment_bytes(b"refresh_token", b"UnknownSecretValueB8Y7X6")
        )
        scan = workspace._scan_secret_value(
            payload,
            _event_budget=budget,
        )
        self.assertEqual(scan.blocking_rule, "generic-secret-assignment")
        self.assertEqual(budget.remaining, 0)

        with self.assertRaisesRegex(ReviewError, "requires accepted-candidate capture"):
            workspace._scan_secret_value(
                payload,
                _continue_after_blocking=True,
            )

        with self.assertRaisesRegex(ReviewError, "scanner event limit"):
            workspace._scan_secret_value(
                payload,
                capture_accepted_candidates=True,
                _event_budget=workspace.SecretScanBudget(1),
                _continue_after_blocking=True,
            )

    def test_blocking_candidate_capture_is_exhaustive_deduplicated_and_exact(
        self,
    ) -> None:
        unknown_a = reduction_secret("generic-secret-assignment", b"A")
        unknown_b = reduction_secret("generic-secret-assignment", b"B")
        provider = reduction_secret("github-token", b"C")
        private_key = reduction_secret("private-key", b"D")
        payload = b"\n".join(
            (
                private_key,
                assignment_bytes(b"access_token", unknown_a),
                assignment_bytes(b"refresh_token", unknown_b),
                assignment_bytes(b"api_token", provider),
            )
        )

        scan = workspace._scan_secret_value(
            payload,
            capture_blocking_candidates=True,
            _continue_after_blocking=True,
        )

        self.assertIsNone(scan.blocking_rule)
        self.assertEqual(
            scan.blocking_candidates,
            {
                unknown_a: {"generic-secret-assignment"},
                unknown_b: {"generic-secret-assignment"},
                provider: {"github-token"},
                private_key: {"private-key"},
            },
        )

    def test_unextractable_secret_shapes_remain_blockers_during_capture(self) -> None:
        normal_jwt_segment = b"B" * 12
        pem_begin = b"-----BEGIN " + b"PRIVATE KEY-----\n"
        cases = (
            ("provider-prefix", "github-token", b"ghp_" + b"A" * 513),
            (
                "oversized-jwt",
                "jwt",
                b"eyJ"
                + b"C" * 2049
                + b"."
                + normal_jwt_segment
                + b"."
                + normal_jwt_segment,
            ),
            (
                "oversized-generic",
                "generic-secret-assignment",
                assignment_bytes(b"password", b"D" * 513),
            ),
            ("unclosed-pem", "private-key", pem_begin + b"E" * 64),
            (
                "oversized-pem",
                "private-key",
                pem_begin + b"F" * workspace.MAX_PEM_SECRET_BYTES,
            ),
        )
        for label, expected_rule, payload in cases:
            with self.subTest(case=label):
                scan = workspace._scan_secret_value(
                    payload,
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                )
                self.assertEqual(scan.blocking_rule, expected_rule)
                self.assertFalse(scan.blocking_candidates)

    def test_dense_unclosed_pem_markers_use_the_preindexed_end_markers(self) -> None:
        class FindCountingBytes(bytes):
            def __new__(cls, value: bytes):
                instance = super().__new__(cls, value)
                instance.find_calls = 0
                return instance

            def find(self, *args):
                self.find_calls += 1
                return super().find(*args)

        marker_count = 512
        begin_marker = b"-----BEGIN " + b"PRIVATE KEY-----"
        payload = FindCountingBytes(b"\n".join((begin_marker,) * marker_count))

        events = tuple(workspace._iter_secret_events(payload))

        self.assertEqual(
            sum(
                rule == "private-key" and candidate is None
                for rule, candidate, *_rest in events
            ),
            marker_count,
        )
        self.assertEqual(payload.find_calls, 0)

    def test_provider_body_continuation_cannot_be_captured_as_a_512_byte_prefix(
        self,
    ) -> None:
        prefix = b"glpat-" + b"A" * 512
        payload = prefix + b"-suffix"

        scan = workspace._scan_secret_value(
            payload,
            capture_blocking_candidates=True,
            _continue_after_blocking=True,
        )

        self.assertEqual(len(scan.blocking_candidates), 0)
        self.assertEqual(scan.blocking_rule, "gitlab-token")

    def test_provider_body_continuation_crossing_first_commit_is_not_captured(
        self,
    ) -> None:
        first_read = (
            workspace.MAX_SECRET_PREFIX_PROOF_BYTES + workspace.STREAM_SCAN_OVERLAP
        )
        committed_end = first_read - workspace.STREAM_SCAN_OVERLAP
        candidate = b"glpat-" + b"A" * 512
        candidate_start = committed_end - len(candidate)
        payload = (
            b"x" * (candidate_start - 1)
            + b"\n"
            + candidate
            + b"-suffix\n"
            + b"x" * workspace.STREAM_SCAN_OVERLAP
        )
        self.assertGreater(len(payload), first_read)

        scan = workspace._stream_secret_scan(
            io.BytesIO(payload),
            size=len(payload),
            capture_blocking_candidates=True,
            _continue_after_blocking=True,
        )

        self.assertEqual(len(scan.blocking_candidates), 0)
        self.assertEqual(scan.blocking_rule, "gitlab-token")

    def test_google_api_key_body_continuation_keeps_complete_stream_candidate(
        self,
    ) -> None:
        truncated = b"AIza" + b"A" * 34 + b"-"
        complete = truncated + b"Z"
        exact_scan = workspace._scan_secret_value(
            truncated,
            capture_blocking_candidates=True,
            _continue_after_blocking=True,
        )
        self.assertIsNone(exact_scan.blocking_rule)
        self.assertEqual(
            exact_scan.blocking_candidates,
            {truncated: {"google-api-key"}},
        )
        first_read = (
            workspace.MAX_SECRET_PREFIX_PROOF_BYTES + workspace.STREAM_SCAN_OVERLAP
        )
        committed_end = first_read - workspace.STREAM_SCAN_OVERLAP
        candidate_start = committed_end - len(truncated)
        payload = (
            b"x" * (candidate_start - 1)
            + b"\n"
            + complete
            + b"!\n"
            + b"x" * workspace.STREAM_SCAN_OVERLAP
        )
        self.assertGreater(len(payload), first_read)

        scan = workspace._stream_secret_scan(
            io.BytesIO(payload),
            size=len(payload),
            capture_blocking_candidates=True,
            _continue_after_blocking=True,
        )

        self.assertIsNone(scan.blocking_rule)
        self.assertEqual(
            scan.blocking_candidates,
            {complete: {"google-api-key"}},
        )
        self.assertNotIn(truncated, scan.blocking_candidates)

    def test_valid_long_provider_candidates_are_not_prefix_only_by_total_length(
        self,
    ) -> None:
        cases = (
            ("openai-key", b"sk-proj-B1" + b"B" * 506),
            ("github-token", b"github_pat_C2" + b"C" * 504),
        )
        for expected_rule, candidate in cases:
            with self.subTest(rule=expected_rule):
                scan = workspace._scan_secret_value(
                    candidate,
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                )
                self.assertIsNone(scan.blocking_rule)
                self.assertEqual(
                    scan.blocking_candidates,
                    {candidate: {expected_rule}},
                )

    def test_valid_long_provider_candidates_suppress_exact_oversized_assignments(
        self,
    ) -> None:
        cases = (
            ("openai-key", b"sk-proj-B1" + b"B" * 506),
            ("github-token", b"github_pat_C2" + b"C" * 504),
        )
        for expected_rule, candidate in cases:
            for quoted, payload in (
                (True, assignment_bytes(b"api_token", candidate)),
                (False, b"api_" + b"token = " + candidate + b"\n"),
            ):
                with self.subTest(rule=expected_rule, quoted=quoted):
                    scan = workspace._scan_secret_value(
                        payload,
                        capture_blocking_candidates=True,
                        _continue_after_blocking=True,
                    )
                    self.assertIsNone(scan.blocking_rule)
                    self.assertEqual(
                        scan.blocking_candidates,
                        {candidate: {expected_rule}},
                    )

                    adjacent = workspace._scan_secret_value(
                        (
                            assignment_bytes(b"api_token", candidate + b"!")
                            if quoted
                            else b"api_" + b"token = " + candidate + b"!\n"
                        ),
                        capture_blocking_candidates=True,
                        _continue_after_blocking=True,
                    )
                    self.assertEqual(
                        adjacent.blocking_rule,
                        "generic-secret-assignment",
                    )

    def test_long_provider_candidate_does_not_suppress_unsafe_assignment_rhs(
        self,
    ) -> None:
        candidate = b"sk-" + b"proj-B1" + b"B" * 506
        assignment_prefix = b"api_" + b"token = "
        cases = (
            (
                "unquoted-space-continuation",
                assignment_prefix + candidate + b" \\" + b"\ncontinued\n",
                False,
            ),
            (
                "unquoted-space-operator",
                assignment_prefix + candidate + b" + continued\n",
                False,
            ),
            (
                "unquoted-double-quote",
                assignment_prefix + candidate + b'"continued"\n',
                False,
            ),
            (
                "unquoted-single-quote",
                assignment_prefix + candidate + b"'continued'\n",
                False,
            ),
            (
                "unquoted-backslash",
                assignment_prefix + candidate + b"\\continued\n",
                False,
            ),
            (
                "unquoted-backtick",
                assignment_prefix + candidate + b"`continued`\n",
                False,
            ),
            (
                "quoted-operator",
                assignment_bytes(b"api_" + b"token", candidate) + b" + continued\n",
                False,
            ),
            (
                "diff-same-side-continuation",
                b"+" + assignment_prefix + candidate + b"\n+  + continued\n",
                True,
            ),
        )
        for label, payload, diff_surface in cases:
            with self.subTest(case=label):
                scan = workspace._scan_secret_value(
                    payload,
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                    diff_surface=diff_surface,
                )

                self.assertEqual(
                    scan.blocking_rule,
                    "generic-secret-assignment",
                )
                self.assertEqual(
                    scan.blocking_candidates,
                    {candidate: {"openai-key"}},
                )

    def test_short_provider_candidate_keeps_unsafe_unquoted_rhs_blocker(
        self,
    ) -> None:
        candidate = b"ghp_" + b"A" * 36
        assignment_prefix = b"api_" + b"token = "
        cases = (
            (
                "space-operator",
                assignment_prefix + candidate + b" + continued\n",
                False,
            ),
            (
                "shell-continuation",
                assignment_prefix + candidate + b" \\" + b"\ncontinued\n",
                False,
            ),
            (
                "diff-same-side-continuation",
                b"+" + assignment_prefix + candidate + b"\n+  + continued\n",
                True,
            ),
        )
        for label, payload, diff_surface in cases:
            with self.subTest(case=label):
                scan = workspace._scan_secret_value(
                    payload,
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                    diff_surface=diff_surface,
                )

                self.assertEqual(
                    scan.blocking_rule,
                    "generic-secret-assignment",
                )
                self.assertEqual(
                    scan.blocking_candidates,
                    {candidate: {"github-token"}},
                )

    def test_provider_prefix_keeps_complete_low_entropy_candidate(self) -> None:
        ordinary_cases = (
            ("aws-access-key", b"AKIA" + b"A" * 16),
            ("anthropic-key", b"sk-" + b"ant-" + b"A" * 32),
            ("openai-key", b"sk-" + b"A" * 32),
            ("github-token", b"ghp_" + b"A" * 36),
            ("github-pat", b"github_" + b"pat_" + b"A" * 20),
            ("gitlab-token", b"glpat-" + b"A" * 20),
            ("google-api-key", b"AI" + b"za" + b"A" * 35),
            ("npm-token", b"npm_" + b"A" * 36),
            ("pypi-token", b"pypi-" + b"A" * 50),
            ("slack-token", b"xoxb-" + b"A" * 20),
            ("stripe-live-key", b"sk_" + b"live_" + b"A" * 16),
            (
                "jwt",
                b"eyJ" + b"A" * 12 + b"." + b"A" * 12 + b"." + b"A" * 12,
            ),
        )
        for label, candidate in ordinary_cases:
            with self.subTest(rule=label):
                complete_candidate = candidate + b"+alpha"
                scan = workspace._scan_secret_value(
                    b"api_" + b"token = " + complete_candidate + b"\n",
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                )

                self.assertIsNone(scan.blocking_rule)
                self.assertEqual(
                    scan.blocking_candidates[complete_candidate],
                    {"generic-secret-assignment"},
                )

        candidate = b"ghp_" + b"A" * 36
        wrapped_candidate = b"wrap/" + candidate + b"+alpha"
        wrapped_scan = workspace._scan_secret_value(
            b"api_" + b"token = " + wrapped_candidate + b"\n",
            capture_blocking_candidates=True,
            _continue_after_blocking=True,
        )
        self.assertEqual(
            wrapped_scan.blocking_candidates[wrapped_candidate],
            {"generic-secret-assignment"},
        )

        aws_candidate = b"A" * 40
        aws_complete_candidate = aws_candidate + b"+alpha"
        aws_scan = workspace._scan_secret_value(
            b"aws_" + b"secret_access_key = " + aws_complete_candidate + b"\n",
            capture_blocking_candidates=True,
            _continue_after_blocking=True,
        )
        self.assertEqual(
            aws_scan.blocking_candidates[aws_complete_candidate],
            {"generic-secret-assignment"},
        )

    def test_fixed_length_provider_suffix_keeps_complete_rhs_identity(
        self,
    ) -> None:
        cases = (
            ("aws-access-key", b"AKIA" + b"A" * 16),
            ("npm-token", b"npm_" + b"A" * 36),
        )
        for rule, candidate in cases:
            with self.subTest(rule=rule):
                complete_candidate = candidate + b"_suffix"
                scan = workspace._scan_secret_value(
                    b"api_" + b"token = " + complete_candidate + b"\n",
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                )

                self.assertIsNone(scan.blocking_rule)
                self.assertEqual(
                    scan.blocking_candidates[candidate],
                    {rule},
                )
                self.assertEqual(
                    scan.blocking_candidates[complete_candidate],
                    {"generic-secret-assignment"},
                )

                body_continuation = workspace._scan_secret_value(
                    b"api_" + b"token = " + candidate + b"A\n",
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                )
                self.assertNotIn(candidate, body_continuation.blocking_candidates)

    def test_unclosed_or_mismatched_rhs_wrapper_keeps_generic_blocker(
        self,
    ) -> None:
        candidate = b"ghp_" + b"A" * 36
        cases = (
            ("unclosed-unquoted", b"api_token = (" + candidate + b"\n"),
            ("wrong-type-unquoted", b"api_token = (" + candidate + b"]\n"),
            (
                "crossed-unquoted",
                b"api_token = ([" + candidate + b")]\n",
            ),
            ("mismatched-unquoted", b"api_token = ([" + candidate + b")\n"),
            ("extra-unquoted", b"api_token = (" + candidate + b"))\n"),
            ("unclosed-quoted", b'api_token = ("' + candidate + b'"\n'),
            (
                "mismatched-quoted",
                b'api_token = (["' + candidate + b'")\n',
            ),
            (
                "crossed-quoted",
                b'api_token = (["' + candidate + b'")]\n',
            ),
            (
                "expression-before-quote",
                b'api_token = fallback or "' + candidate + b'"\n',
            ),
            (
                "closed-wrapper-before-quote",
                b'api_token = ()"' + candidate + b'"\n',
            ),
            (
                "external-function-mismatch",
                b'configure(api_token = "' + candidate + b'"]\n',
            ),
            (
                "external-json-mismatch",
                b'[{"api_token": "' + candidate + b'")]\n',
            ),
            (
                "external-function-missing",
                b'configure(api_token = "' + candidate + b'"\n',
            ),
            (
                "external-json-missing",
                b'[{"api_token": "' + candidate + b'"}\n',
            ),
            (
                "external-function-missing-after-sibling",
                b'configure(api_token = "' + candidate + b'", state = "expired"\n',
            ),
            (
                "external-function-string-closer-after-sibling",
                b'configure(api_token = "' + candidate + b'", state = ")"\n',
            ),
            (
                "external-json-missing-after-sibling",
                b'[{"api_token": "' + candidate + b'", "state": "expired"}\n',
            ),
            (
                "unclosed-source-string-across-line",
                b'payload = "\napi_token = "' + candidate + b'"\n',
            ),
            (
                "unclosed-triple-source-string",
                b'payload = """\napi_token = "' + candidate + b'"\n',
            ),
            (
                "escaped-source-string-prefix",
                b'payload = "prefix\\n api_token = "' + candidate + b'"\n',
            ),
            (
                "unclosed-block-comment-prefix",
                b'/* fixture api_token = "' + candidate + b'"\n',
            ),
            (
                "unclosed-line-comment-prefix",
                b'// fixture api_token = "' + candidate + b'"',
            ),
            (
                "unclosed-hash-comment-prefix",
                b'# fixture api_token = "' + candidate + b'"',
            ),
            (
                "nested-source-marker",
                b'payload = "br\'configure(api_token = "'
                + candidate
                + b'", state = "expired")\'\n',
            ),
            (
                "triple-source-missing-logical-closer",
                b"payload = b'''configure(api_token = \""
                + candidate
                + b"\", state = \"expired\"'''\n",
            ),
            (
                "external-function-missing-before-statement",
                b'configure(api_token = "' + candidate + b'"\nstate = "expired"\n',
            ),
            (
                "diff-external-function-mismatch",
                b"@@ -1 +1 @@\n" + b'+configure(api_token = "' + candidate + b'"]\n',
            ),
            (
                "diff-external-json-mismatch",
                b"@@ -1 +1 @@\n" + b'+[{"api_token": "' + candidate + b'")]\n',
            ),
            (
                "diff-external-function-missing",
                b"@@ -1 +1 @@\n" + b'+configure(api_token = "' + candidate + b'"\n',
            ),
            (
                "diff-external-json-missing",
                b"@@ -1 +1 @@\n" + b'+[{"api_token": "' + candidate + b'"}\n',
            ),
            (
                "diff-external-function-missing-after-sibling",
                b"@@ -1 +1,2 @@\n"
                + b'+configure(api_token = "'
                + candidate
                + b'",\n'
                + b'+    state = "expired"\n',
            ),
            (
                "diff-external-function-opposite-only-closer",
                b"@@ -1 +1,2 @@\n"
                + b'+configure(api_token = "'
                + candidate
                + b'"\n'
                + b"-)\n",
            ),
        )
        for label, payload in cases:
            with self.subTest(case=label):
                scan = workspace._scan_secret_value(
                    payload,
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                    diff_surface=label.startswith("diff-"),
                )

                self.assertEqual(
                    scan.blocking_rule,
                    "generic-secret-assignment",
                )
                self.assertEqual(
                    scan.blocking_candidates,
                    {candidate: {"github-token"}},
                )

    def test_unclosed_rhs_wrapper_preserves_incomplete_suffix_state(self) -> None:
        candidate = b"ghp_" + b"A" * 36
        cases = (
            b"api_token = (" + candidate,
            b'configure(api_token = "' + candidate + b'"',
            b'[{"api_token": "' + candidate + b'"}',
            b'configure(api_token = "' + candidate + b'", state = "expired"',
            b'[{"api_token": "' + candidate + b'", "state": "expired"}',
        )
        for payload in cases:
            with self.subTest(payload=payload):
                scan = workspace._scan_secret_value(
                    payload,
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                    suffix_context_complete=False,
                )

                self.assertIsNone(scan.blocking_rule)
                self.assertIsNotNone(scan.incomplete_suffix_start)
                self.assertEqual(
                    scan.blocking_candidates,
                    {candidate: {"github-token"}},
                )

    def test_provider_rhs_discovery_is_bounded_by_specific_spans_and_budget(
        self,
    ) -> None:
        class ForbiddenPattern:
            def finditer(self, _value: bytes):
                raise AssertionError("assignment discovery should be skipped")

        assignment_prefix = b"pass" + b"word="
        repeated_keys = assignment_prefix * (256 * 1024 // len(assignment_prefix))
        with mock.patch.object(
            workspace,
            "SECRET_ASSIGNMENT_PREFIX",
            ForbiddenPattern(),
        ):
            scan = workspace._scan_secret_value(repeated_keys)
        self.assertEqual(scan.blocking_rule, "generic-secret-assignment")

        candidate = b"ghp_" + b"A" * 36
        committed_payload = candidate + b"\n" + repeated_keys
        with mock.patch.object(
            workspace,
            "SECRET_ASSIGNMENT_PREFIX",
            ForbiddenPattern(),
        ):
            committed_scan = workspace._scan_secret_value(
                committed_payload,
                minimum_end=len(committed_payload),
            )
        self.assertIsNone(committed_scan.blocking_rule)

        provider_payload = assignment_prefix * 64 + candidate + b"\n"
        budget = workspace.SecretScanBudget(
            workspace.MAX_SECRET_SCAN_EVENTS,
            remaining_prefix_proof_bytes=64,
        )
        with self.assertRaisesRegex(ReviewError, "prefix proof limit"):
            workspace._scan_secret_value(
                provider_payload,
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
                _event_budget=budget,
            )

    def test_provider_rhs_beyond_proof_frontier_is_retained_then_blocked(
        self,
    ) -> None:
        proof_bytes = 256
        overlap = 128
        candidate = b"ghp_" + b"A" * 36
        assignment_prefix = b"api_token = ("
        candidate_start = proof_bytes + 16
        wrapper_count = candidate_start - len(assignment_prefix)
        payload = (
            assignment_prefix
            + b"(" * wrapper_count
            + candidate
            + b")" * (wrapper_count + 1)
            + b"\n"
        )
        self.assertEqual(payload.index(candidate), candidate_start)

        with mock.patch.object(
            workspace,
            "MAX_SECRET_PREFIX_PROOF_BYTES",
            proof_bytes,
        ):
            incomplete = workspace._scan_secret_value(
                payload,
                maximum_end=proof_bytes - 1,
                suffix_context_complete=False,
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )
            frontier = workspace._scan_secret_value(
                payload,
                maximum_end=proof_bytes,
                suffix_context_complete=False,
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )

        self.assertIsNone(incomplete.blocking_rule)
        self.assertEqual(incomplete.incomplete_suffix_start, 0)
        self.assertEqual(incomplete.incomplete_suffix_retention_start, 0)
        self.assertEqual(frontier.blocking_rule, "generic-secret-assignment")
        self.assertIsNone(frontier.incomplete_suffix_start)

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 256),
        ):
            streamed = workspace._stream_secret_scan(
                io.BytesIO(payload),
                size=len(payload),
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )

        self.assertEqual(streamed.blocking_rule, "generic-secret-assignment")
        self.assertEqual(
            streamed.blocking_candidates,
            {candidate: {"github-token"}},
        )

    def test_open_rhs_before_delayed_provider_is_retained_and_blocked(self) -> None:
        proof_bytes = 256
        overlap = 32
        candidate, unsafe, _safe, _ordinary = rhs_proof_boundary_payloads()
        self.assertEqual(unsafe.index(b"api_token"), 200)
        self.assertEqual(unsafe.index(candidate), 400)
        self.assertGreater(unsafe.index(candidate), proof_bytes + overlap)

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 64),
        ):
            direct = workspace._scan_secret_value(
                unsafe,
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )
            streamed = workspace._stream_secret_scan(
                io.BytesIO(unsafe),
                size=len(unsafe),
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )

        self.assertEqual(direct.blocking_rule, "generic-secret-assignment")
        self.assertEqual(
            direct.blocking_candidates,
            {candidate: {"github-token"}},
        )
        self.assertEqual(streamed, direct)

    def test_closed_rhs_releases_remote_provider_to_standalone_scan(self) -> None:
        proof_bytes = 256
        overlap = 32
        candidate, _unsafe, safe, _ordinary = rhs_proof_boundary_payloads()
        self.assertEqual(safe.index(b"api_token"), 200)
        self.assertEqual(safe.index(candidate), 500)
        self.assertGreater(safe.index(candidate), 200 + proof_bytes)

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 64),
        ):
            direct = workspace._scan_secret_value(
                safe,
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )
            streamed = workspace._stream_secret_scan(
                io.BytesIO(safe),
                size=len(safe),
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )

        self.assertIsNone(direct.blocking_rule)
        self.assertEqual(
            direct.blocking_candidates,
            {candidate: {"github-token"}},
        )
        self.assertEqual(streamed, direct)

    def test_closed_rhs_without_provider_is_not_retained_or_overcharged(self) -> None:
        class SliceCountingBytes(bytes):
            def __new__(cls, value: bytes):
                instance = super().__new__(cls, value)
                instance.maximum_slice = 0
                return instance

            def __getitem__(self, key):
                if isinstance(key, slice) and key.step in (None, 1):
                    start, stop, _step = key.indices(len(self))
                    self.maximum_slice = max(self.maximum_slice, stop - start)
                return super().__getitem__(key)

        proof_bytes = 256
        overlap = 32
        _candidate, _unsafe, _safe, ordinary = rhs_proof_boundary_payloads()
        marker = b'api_token = "placeholder"'
        recorded_values: list[bytes] = []
        scan_secret_value = workspace._scan_secret_value

        def record_scan(value: bytes, *args, **kwargs):
            recorded_values.append(value)
            return scan_secret_value(value, *args, **kwargs)

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 64),
            mock.patch.object(
                workspace,
                "_scan_secret_value",
                side_effect=record_scan,
            ),
        ):
            streamed = workspace._stream_secret_scan(
                io.BytesIO(ordinary),
                size=len(ordinary),
            )

        self.assertEqual(streamed, workspace.SecretScanResult.empty())
        self.assertEqual(sum(marker in value for value in recorded_values), 1)
        self.assertTrue(recorded_values)
        self.assertEqual(len(recorded_values[0]), proof_bytes + overlap)
        self.assertTrue(
            all(len(value) <= 64 + 2 * overlap for value in recorded_values[1:])
        )

        placeholder_line = marker + b"\n"
        for repeated_line in (
            placeholder_line,
            b'  api_token = "placeholder"\n',
            b'  "api_token": "placeholder"\n',
            b'  "api_token": "placeholder"\r\n',
            b'api_token = "placeholder"; ',
            b'"api_token": "placeholder"; ',
        ):
            with self.subTest(repeated_line=repeated_line):
                repeated = SliceCountingBytes(
                    repeated_line * 4096 + b'state = "expired"\n'
                )
                budget = workspace.SecretScanBudget(
                    workspace.MAX_SECRET_SCAN_EVENTS,
                    remaining_prefix_proof_bytes=len(repeated),
                )
                repeated_scan = workspace._scan_secret_value(
                    repeated,
                    suffix_context_complete=False,
                    _event_budget=budget,
                )
                self.assertEqual(repeated_scan, workspace.SecretScanResult.empty())
                self.assertGreater(budget.remaining_prefix_proof_bytes, 0)
                self.assertLess(repeated.maximum_slice, 1024)

        distant = b"x" * 128 + b"\n" + placeholder_line
        exhausted_budget = workspace.SecretScanBudget(
            workspace.MAX_SECRET_SCAN_EVENTS,
            remaining_prefix_proof_bytes=64,
        )
        with self.assertRaisesRegex(
            workspace.ReviewError,
            "prefix proof limit",
        ):
            workspace._scan_secret_value(
                distant,
                suffix_context_complete=False,
                _event_budget=exhausted_budget,
            )

    def test_closed_rhs_cache_does_not_bypass_absolute_proof_cap(self) -> None:
        proof_bytes = 128
        overlap = 32
        placeholder_line = b'api_token = "placeholder"\n'
        payload = placeholder_line * 8 + b"x" * (proof_bytes + overlap)

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 64),
        ):
            direct = workspace._scan_secret_value(payload)
            streamed = workspace._stream_secret_scan(
                io.BytesIO(payload),
                size=len(payload),
            )

        self.assertEqual(direct.blocking_rule, "generic-secret-assignment")
        self.assertEqual(streamed, direct)

    def test_closed_rhs_frontier_starts_after_external_wrapper(self) -> None:
        payload = (
            b'configure(api_token = "placeholder"\n); '
            b'api_token = "placeholder"; state = "expired"'
        )

        scan = workspace._scan_secret_value(
            payload,
            suffix_context_complete=False,
        )

        self.assertEqual(scan, workspace.SecretScanResult.empty())

    def test_open_rhs_without_provider_is_consistent_at_proof_cap(self) -> None:
        proof_bytes = 64
        overlap = 16
        payload = b"x" * 89 + b"\napi_token: |\n" + b"x" * 100 + b"\n"

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 32),
        ):
            direct = workspace._scan_secret_value(
                payload,
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )
            streamed = workspace._stream_secret_scan(
                io.BytesIO(payload),
                size=len(payload),
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )

        self.assertEqual(direct.blocking_rule, "generic-secret-assignment")
        self.assertEqual(direct.blocking_candidates, {})
        self.assertEqual(streamed, direct)

    def test_unknown_multiline_rhs_stays_open_until_the_proof_cap(self) -> None:
        proof_bytes = 64
        overlap = 32
        candidate = reduction_secret("github-token", b"C")
        candidate_start = 100
        prefixes = (
            b"api_token: |\n  first\n",
            b"api_token: >-\n  first\n",
            b"api_token = <<EOF\nfirst\n",
        )
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                payload = (
                    prefix
                    + b"x" * (candidate_start - len(prefix) - 1)
                    + b"\n"
                    + candidate
                    + b"\nEOF\n"
                )
                self.assertEqual(payload.index(candidate), candidate_start)
                self.assertGreater(candidate_start, proof_bytes + overlap)
                with (
                    mock.patch.object(
                        workspace,
                        "MAX_SECRET_PREFIX_PROOF_BYTES",
                        proof_bytes,
                    ),
                    mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
                    mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 64),
                ):
                    direct = workspace._scan_secret_value(
                        payload,
                        capture_blocking_candidates=True,
                        _continue_after_blocking=True,
                    )
                    streamed = workspace._stream_secret_scan(
                        io.BytesIO(payload),
                        size=len(payload),
                        capture_blocking_candidates=True,
                        _continue_after_blocking=True,
                    )

                self.assertEqual(
                    direct.blocking_rule,
                    "generic-secret-assignment",
                )
                self.assertEqual(
                    direct.blocking_candidates,
                    {candidate: {"github-token"}},
                )
                self.assertEqual(streamed, direct)

    def test_completed_scan_blocks_open_rhs_after_an_earlier_provider(
        self,
    ) -> None:
        proof_bytes = 64
        overlap = 32
        candidate = reduction_secret("github-token", b"C")
        payload = candidate + b"\napi_token: |\n  first\n" + b"x" * 90 + b"\n"

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 64),
        ):
            direct = workspace._scan_secret_value(
                payload,
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )
            streamed = workspace._stream_secret_scan(
                io.BytesIO(payload),
                size=len(payload),
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )

        self.assertEqual(direct.blocking_rule, "generic-secret-assignment")
        self.assertEqual(
            direct.blocking_candidates,
            {candidate: {"github-token"}},
        )
        self.assertEqual(streamed, direct)

    def test_rhs_closure_proves_external_source_context_before_release(self) -> None:
        proof_bytes = 64
        overlap = 32
        candidate_start = 100
        candidate = reduction_secret("github-token", b"C")
        cases = (
            (
                "unclosed-source-string",
                b'payload = "\napi_token = "placeholder"\nstate = "expired"\n',
                True,
            ),
            (
                "unclosed-triple-source-string",
                b'payload = """\napi_token = "placeholder"\nstate = "expired"\n',
                True,
            ),
            (
                "unclosed-block-comment",
                b'/* fixture\napi_token = "placeholder"\nstate = "expired"\n',
                True,
            ),
            (
                "closed-function-wrapper",
                b'configure(api_token = "placeholder")\nstate = "expired"\n',
                False,
            ),
        )
        provider_prefix = b"wrap/"
        for label, prefix, should_block in cases:
            with self.subTest(case=label):
                payload = (
                    prefix
                    + b"x" * (candidate_start - len(prefix) - len(provider_prefix))
                    + provider_prefix
                    + candidate
                    + b"+alpha\n"
                )
                self.assertEqual(payload.index(candidate), candidate_start)
                with (
                    mock.patch.object(
                        workspace,
                        "MAX_SECRET_PREFIX_PROOF_BYTES",
                        proof_bytes,
                    ),
                    mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
                    mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 64),
                ):
                    direct = workspace._scan_secret_value(
                        payload,
                        capture_blocking_candidates=True,
                        _continue_after_blocking=True,
                    )
                    streamed = workspace._stream_secret_scan(
                        io.BytesIO(payload),
                        size=len(payload),
                        capture_blocking_candidates=True,
                        _continue_after_blocking=True,
                    )

                self.assertEqual(
                    direct.blocking_rule,
                    "generic-secret-assignment" if should_block else None,
                )
                self.assertEqual(
                    direct.blocking_candidates,
                    {candidate: {"github-token"}},
                )
                self.assertEqual(streamed, direct)

    def test_provider_rhs_span_and_wrapper_proof_cannot_cross_cap(self) -> None:
        proof_bytes = 64
        candidate = b"ghp_" + b"A" * 36
        cases = (
            (
                "provider-span",
                b"api_token = "
                + b"(" * 37
                + b'"'
                + candidate
                + b'"'
                + b")" * 37
                + b"\n",
            ),
            (
                "direct-quoted-provider-span",
                b"api_token = " + b" " * 20 + b'"' + candidate + b'"\n',
            ),
            (
                "outer-wrappers",
                b"api_token = "
                + b"(" * 10
                + b'"'
                + candidate
                + b'"'
                + b")" * 10
                + b"\n",
            ),
            (
                "tail-terminator",
                b"api_token = " + b" " * 10 + b'"' + candidate + b'";\n',
            ),
        )
        for label, payload in cases:
            with self.subTest(case=label):
                normal_cap = workspace._scan_secret_value(
                    payload,
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                )
                with mock.patch.object(
                    workspace,
                    "MAX_SECRET_PREFIX_PROOF_BYTES",
                    proof_bytes,
                ):
                    before_frontier = workspace._scan_secret_value(
                        payload,
                        maximum_end=proof_bytes - 1,
                        suffix_context_complete=False,
                        capture_blocking_candidates=True,
                        _continue_after_blocking=True,
                    )
                    at_frontier = workspace._scan_secret_value(
                        payload,
                        maximum_end=proof_bytes,
                        suffix_context_complete=False,
                        capture_blocking_candidates=True,
                        _continue_after_blocking=True,
                    )
                    complete = workspace._scan_secret_value(
                        payload,
                        capture_blocking_candidates=True,
                        _continue_after_blocking=True,
                    )

                self.assertIsNone(normal_cap.blocking_rule)
                self.assertEqual(
                    normal_cap.blocking_candidates,
                    {candidate: {"github-token"}},
                )
                self.assertIsNone(before_frontier.blocking_rule)
                self.assertEqual(before_frontier.incomplete_suffix_start, 0)
                self.assertEqual(
                    at_frontier.blocking_rule,
                    "generic-secret-assignment",
                )
                self.assertEqual(
                    complete.blocking_rule,
                    "generic-secret-assignment",
                )
                self.assertEqual(
                    complete.blocking_candidates,
                    {candidate: {"github-token"}},
                )

        with mock.patch.object(
            workspace,
            "MAX_SECRET_PREFIX_PROOF_BYTES",
            proof_bytes,
        ):
            short_incomplete = workspace._scan_secret_value(
                b'api_token = "' + candidate + b'"',
                suffix_context_complete=False,
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )
        self.assertIsNone(short_incomplete.blocking_rule)
        self.assertEqual(short_incomplete.incomplete_suffix_start, 0)

    def test_provider_rhs_cap_does_not_copy_absolute_proof_prefix(self) -> None:
        class SliceCountingBytes(bytes):
            def __new__(cls, value: bytes):
                instance = super().__new__(cls, value)
                instance.slice_reads = []
                return instance

            def __getitem__(self, key):
                if isinstance(key, slice) and key.step in (None, 1):
                    start, stop, _step = key.indices(len(self))
                    self.slice_reads.append((start, stop))
                return super().__getitem__(key)

        proof_bytes = 1024
        assignment_start = 512
        candidate = b"ghp_" + b"A" * 36
        assignment_prefix = b"api_token = ("
        candidate_start = assignment_start + proof_bytes + 16
        wrapper_count = candidate_start - assignment_start - len(assignment_prefix)
        payload = SliceCountingBytes(
            b"x" * (assignment_start - 1)
            + b"\n"
            + assignment_prefix
            + b"(" * wrapper_count
            + candidate
            + b")" * (wrapper_count + 1)
            + b"\n"
        )

        with mock.patch.object(
            workspace,
            "MAX_SECRET_PREFIX_PROOF_BYTES",
            proof_bytes,
        ):
            scan = workspace._scan_secret_value(
                payload,
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )

        self.assertEqual(scan.blocking_rule, "generic-secret-assignment")
        self.assertEqual(
            scan.blocking_candidates,
            {candidate: {"github-token"}},
        )
        absolute_proof_end = assignment_start + proof_bytes
        self.assertNotIn((0, absolute_proof_end), payload.slice_reads)
        self.assertLess(
            max((stop - start for start, stop in payload.slice_reads), default=0),
            proof_bytes,
        )

    def test_provider_rhs_whitespace_lookahead_is_linear(self) -> None:
        class IndexCountingBytes(bytes):
            def __new__(cls, value: bytes):
                instance = super().__new__(cls, value)
                instance.integer_reads = Counter()
                return instance

            def __getitem__(self, key):
                if isinstance(key, int) and key >= 0:
                    self.integer_reads[key] += 1
                return super().__getitem__(key)

        whitespace_count = 512
        candidate = b"ghp_" + b"A" * 36
        assignment_prefix = b"api_token = ("
        payload = IndexCountingBytes(
            assignment_prefix + b" " * whitespace_count + candidate + b")\n"
        )
        scan = workspace._scan_secret_value(
            payload,
            capture_blocking_candidates=True,
            _continue_after_blocking=True,
        )

        self.assertIsNone(scan.blocking_rule)
        self.assertEqual(
            scan.blocking_candidates,
            {candidate: {"github-token"}},
        )
        whitespace_reads = tuple(
            payload.integer_reads[index]
            for index in range(
                len(assignment_prefix),
                len(assignment_prefix) + whitespace_count,
            )
        )
        self.assertLessEqual(max(whitespace_reads), 6)
        self.assertLessEqual(sum(whitespace_reads), whitespace_count * 6)

    def test_short_provider_candidate_keeps_incomplete_quoted_rhs_blocker(
        self,
    ) -> None:
        candidate = b"ghp_" + b"A" * 36
        assignment_prefix = b"api_" + b'token = "'
        cases = (
            (
                "shell-continuation",
                assignment_prefix + candidate + b'\\\ncontinued"\n',
                False,
            ),
            (
                "diff-same-side-continuation",
                b"+" + assignment_prefix + candidate + b'\\\n+continued"\n',
                True,
            ),
            (
                "single-quote-crlf",
                b"api_" + b"token = '" + candidate + b"\\\r\ncontinued'\r\n",
                False,
            ),
            (
                "raw-prefix",
                b"api_" + b'token = r"' + candidate + b'\\\ncontinued"\n',
                False,
            ),
            (
                "triple-quoted",
                b"api_" + b'token = """' + candidate + b'\ncontinued"""\n',
                False,
            ),
            (
                "provider-on-later-line",
                b"api_" + b'token = "\\\n' + candidate + b'\\\ncontinued"\n',
                False,
            ),
            (
                "unclosed-at-eof",
                assignment_prefix + candidate,
                False,
            ),
        )
        for label, payload, diff_surface in cases:
            with self.subTest(case=label):
                scan = workspace._scan_secret_value(
                    payload,
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                    diff_surface=diff_surface,
                )

                self.assertEqual(
                    scan.blocking_rule,
                    "generic-secret-assignment",
                )
                self.assertEqual(
                    scan.blocking_candidates,
                    {candidate: {"github-token"}},
                )

    def test_escaped_quotes_do_not_hide_nested_short_provider_candidate(
        self,
    ) -> None:
        candidate = b"ghp_" + b"A" * 36
        cases = (
            (
                "double-quoted",
                b'api_token = "prefix\\"wrap/' + candidate + b'+alpha"\n',
            ),
            (
                "single-quoted",
                b"api_token = 'prefix\\'wrap/" + candidate + b"+alpha'\n",
            ),
            (
                "triple-quoted",
                b'api_token = """prefix\\"""wrap/' + candidate + b'+alpha"""\n',
            ),
        )
        for label, payload in cases:
            with self.subTest(case=label):
                scan = workspace._scan_secret_value(
                    payload,
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                )

                self.assertEqual(
                    scan.blocking_rule,
                    "generic-secret-assignment",
                )
                self.assertEqual(
                    scan.blocking_candidates,
                    {candidate: {"github-token"}},
                )

    def test_adjacent_quoted_rhs_keeps_nested_short_provider_blocker(
        self,
    ) -> None:
        candidate = b"ghp_" + b"A" * 36
        cases = (
            (
                "adjacent",
                b'api_token = "x" "wrap/' + candidate + b'+alpha"\n',
            ),
            (
                "even-backslashes",
                b'api_token = "x\\\\" "wrap/' + candidate + b'+alpha"\n',
            ),
            (
                "triple-first-literal",
                b'api_token = """x""" "wrap/' + candidate + b'+alpha"\n',
            ),
            (
                "operator",
                b'api_token = "x" + "wrap/' + candidate + b'+alpha"\n',
            ),
        )
        for label, payload in cases:
            with self.subTest(case=label):
                scan = workspace._scan_secret_value(
                    payload,
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                )

                self.assertEqual(
                    scan.blocking_rule,
                    "generic-secret-assignment",
                )
                self.assertEqual(
                    scan.blocking_candidates,
                    {candidate: {"github-token"}},
                )

    def test_parenthesized_quoted_rhs_keeps_nested_short_provider_blocker(
        self,
    ) -> None:
        candidate = b"ghp_" + b"A" * 36
        cases = (
            (
                "single-literal",
                b'api_token = ("wrap/' + candidate + b'+alpha")\n',
            ),
            (
                "adjacent-literals",
                b'api_token = ("x" "wrap/' + candidate + b'+alpha")\n',
            ),
            (
                "multiline",
                b'api_token = (\n    "wrap/' + candidate + b'+alpha"\n)\n',
            ),
            (
                "nested",
                b'api_token = [{("wrap/' + candidate + b'+alpha")}]\n',
            ),
            (
                "function-call",
                b'api_token = build("wrap/' + candidate + b'+alpha")\n',
            ),
            (
                "prefix-expression",
                b'api_token = fallback or "wrap/' + candidate + b'+alpha"\n',
            ),
            (
                "unquoted-wrapper",
                b"api_token = (wrap/" + candidate + b"+alpha)\n",
            ),
        )
        for label, payload in cases:
            with self.subTest(case=label):
                scan = workspace._scan_secret_value(
                    payload,
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                )

                self.assertEqual(
                    scan.blocking_rule,
                    "generic-secret-assignment",
                )
                self.assertEqual(
                    scan.blocking_candidates,
                    {candidate: {"github-token"}},
                )

    def test_diff_opposite_side_delimiter_does_not_close_quoted_rhs(self) -> None:
        candidate = b"ghp_" + b"A" * 36
        payload = (
            b"@@ -1,2 +1,4 @@\n"
            + b'+api_token = """prefix\n'
            + b" context\n"
            + b'-"""\n'
            + b"+other = wrap/"
            + candidate
            + b"+alpha\n"
            + b'+"""\n'
        )

        scan = workspace._scan_secret_value(
            payload,
            capture_blocking_candidates=True,
            diff_surface=True,
            _continue_after_blocking=True,
        )

        self.assertEqual(
            scan.blocking_rule,
            "generic-secret-assignment",
        )
        self.assertEqual(
            scan.blocking_candidates,
            {candidate: {"github-token"}},
        )

    def test_multiline_expression_keeps_nested_short_provider_blocker(self) -> None:
        candidate = b"ghp_" + b"A" * 36
        cases = (
            (
                "trailing-operator",
                b'api_token = prefix +\n  "wrap/' + candidate + b'+alpha"\n',
                False,
            ),
            (
                "leading-operator",
                b'api_token = prefix\n  + "wrap/' + candidate + b'+alpha"\n',
                False,
            ),
            (
                "ternary",
                b'api_token = condition ?\n  "wrap/'
                + candidate
                + b'+alpha" : fallback\n',
                False,
            ),
            (
                "block-comment",
                b'api_token = prefix + /* comment\n  */ "wrap/'
                + candidate
                + b'+alpha"\n',
                False,
            ),
            (
                "line-comment",
                b'api_token = prefix + // comment\n  "wrap/' + candidate + b'+alpha"\n',
                False,
            ),
            (
                "blank-line",
                b'api_token = prefix +\n\n  "wrap/' + candidate + b'+alpha"\n',
                False,
            ),
            (
                "comment-only-line",
                b'api_token = prefix +\n  // comment\n  "wrap/'
                + candidate
                + b'+alpha"\n',
                False,
            ),
            (
                "diff-same-side",
                b"@@ -1 +1,2 @@\n"
                + b"+api_token = prefix +\n"
                + b'+  "wrap/'
                + candidate
                + b'+alpha"\n',
                True,
            ),
            (
                "diff-blank-context",
                b"@@ -1,2 +1,3 @@\n"
                + b"+api_token = prefix +\n"
                + b" \n"
                + b'+  "wrap/'
                + candidate
                + b'+alpha"\n',
                True,
            ),
            (
                "powershell-backtick",
                b"$api_token = $prefix + `\r\n"
                + b'    "wrap/'
                + candidate
                + b'+alpha"\r\n',
                False,
            ),
            (
                "javascript-template",
                b"api_token = `prefix\nwrap/" + candidate + b"+alpha`\n",
                False,
            ),
        )
        for label, payload, diff_surface in cases:
            with self.subTest(case=label):
                scan = workspace._scan_secret_value(
                    payload,
                    capture_blocking_candidates=True,
                    diff_surface=diff_surface,
                    _continue_after_blocking=True,
                )

                self.assertEqual(
                    scan.blocking_rule,
                    "generic-secret-assignment",
                )
                self.assertEqual(
                    scan.blocking_candidates,
                    {candidate: {"github-token"}},
                )

    def test_quoted_assignment_opening_is_retained_before_provider_frontier(
        self,
    ) -> None:
        candidate = b"ghp_" + b"A" * 36
        payload = (
            b"x" * 400
            + b'\napi_token = """'
            + b"y" * 180
            + b"wrap/"
            + candidate
            + b'+alpha"""\n'
        )
        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                512,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", 128),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 256),
        ):
            scan = workspace._stream_secret_scan(
                io.BytesIO(payload),
                size=len(payload),
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )

        self.assertEqual(
            scan.blocking_rule,
            "generic-secret-assignment",
        )
        self.assertEqual(
            scan.blocking_candidates,
            {candidate: {"github-token"}},
        )

        proof_bytes = 512
        overlap = 128
        assignment_start = 80
        candidate_start = 500
        assignment_prefix = b'api_token = "'
        frontier_payload = (
            b"x" * (assignment_start - 1)
            + b"\n"
            + assignment_prefix
            + b"y" * (candidate_start - assignment_start - len(assignment_prefix) - 1)
            + b"/"
            + candidate
            + b'+alpha"\n'
            + b"x" * 256
        )
        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 256),
        ):
            frontier_scan = workspace._stream_secret_scan(
                io.BytesIO(frontier_payload),
                size=len(frontier_payload),
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )

        self.assertEqual(
            frontier_scan.blocking_rule,
            "generic-secret-assignment",
        )
        self.assertEqual(
            frontier_scan.blocking_candidates,
            {candidate: {"github-token"}},
        )

    def test_adjacent_quoted_rhs_is_retained_before_provider_frontier(
        self,
    ) -> None:
        candidate = b"ghp_" + b"A" * 36
        payload = (
            b"x" * 400
            + b'\napi_token = "x"'
            + b" " * 180
            + b'"wrap/'
            + candidate
            + b'+alpha"\n'
        )
        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                512,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", 128),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 256),
        ):
            scan = workspace._stream_secret_scan(
                io.BytesIO(payload),
                size=len(payload),
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )

        self.assertEqual(
            scan.blocking_rule,
            "generic-secret-assignment",
        )
        self.assertEqual(
            scan.blocking_candidates,
            {candidate: {"github-token"}},
        )

    def test_exact_triple_quoted_short_provider_candidate_is_counted_once(
        self,
    ) -> None:
        candidate = b"ghp_" + b"A" * 36
        scan = workspace._scan_secret_value(
            b'api_token = """' + candidate + b'"""\n',
            capture_blocking_candidates=True,
            _continue_after_blocking=True,
        )

        self.assertIsNone(scan.blocking_rule)
        self.assertEqual(
            scan.blocking_candidates,
            {candidate: {"github-token"}},
        )

    def test_exact_parenthesized_short_provider_candidate_is_counted_once(
        self,
    ) -> None:
        candidate = b"ghp_" + b"A" * 36
        cases = (
            (b'api_token = ("' + candidate + b'")\n', False),
            (b"api_token = ([{" + candidate + b"}])\n", False),
            (b'api_token = ([{"' + candidate + b'"}])\n', False),
            (b'configure(api_token = "' + candidate + b'")\n', False),
            (b'[{"api_token": "' + candidate + b'"}]\n', False),
            (
                b"@@ -1 +1 @@\n" + b'+configure(api_token = "' + candidate + b'")\n',
                True,
            ),
            (
                b"@@ -1 +1 @@\n" + b'+[{"api_token": "' + candidate + b'"}]\n',
                True,
            ),
        )
        for payload, diff_surface in cases:
            with self.subTest(payload=payload):
                scan = workspace._scan_secret_value(
                    payload,
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                    diff_surface=diff_surface,
                )

                self.assertIsNone(scan.blocking_rule)
                self.assertEqual(
                    scan.blocking_candidates,
                    {candidate: {"github-token"}},
                )

    def test_exact_template_short_provider_candidate_is_counted_once(self) -> None:
        candidate = b"ghp_" + b"A" * 36
        scan = workspace._scan_secret_value(
            b"api_token = `" + candidate + b"`\n",
            capture_blocking_candidates=True,
            _continue_after_blocking=True,
        )

        self.assertIsNone(scan.blocking_rule)
        self.assertEqual(
            scan.blocking_candidates,
            {candidate: {"github-token"}},
        )

    def test_completed_quoted_assignment_does_not_capture_next_assignment(self) -> None:
        candidate = b"ghp_" + b"A" * 36
        scan = workspace._scan_secret_value(
            b'api_token = "placeholder"\nother_token = ' + candidate + b"\n",
            capture_blocking_candidates=True,
            _continue_after_blocking=True,
        )

        self.assertIsNone(scan.blocking_rule)
        self.assertEqual(
            scan.blocking_candidates,
            {candidate: {"github-token"}},
        )

    def test_safe_short_provider_candidate_is_counted_once(self) -> None:
        candidate = b"ghp_" + b"A" * 36
        cases = (
            ("unquoted", b"api_" + b"token = " + candidate + b"\n"),
            ("quoted", b"api_" + b'token = "' + candidate + b'"\n'),
            ("raw-quoted", b"api_" + b'token = r"' + candidate + b'"\n'),
        )
        for label, payload in cases:
            with self.subTest(case=label):
                scan = workspace._scan_secret_value(
                    payload,
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                )

                self.assertIsNone(scan.blocking_rule)
                self.assertEqual(
                    scan.blocking_candidates,
                    {candidate: {"github-token"}},
                )

    def test_complete_anthropic_candidate_suppresses_openai_prefix_only_event(
        self,
    ) -> None:
        candidate = b"sk-ant-A1" + b"A" * 507
        scan = workspace._scan_secret_value(
            assignment_bytes(b"api_token", candidate),
            capture_blocking_candidates=True,
            _continue_after_blocking=True,
        )

        self.assertIsNone(scan.blocking_rule)
        self.assertEqual(
            scan.blocking_candidates,
            {candidate: {"anthropic-key"}},
        )

    def test_exact_long_provider_assignment_crosses_first_commit_without_blocking(
        self,
    ) -> None:
        candidate = b"sk-proj-" + b"B" * 508
        assignment_prefix = b"api_" + b'token = "'
        first_read = (
            workspace.MAX_SECRET_PREFIX_PROOF_BYTES + workspace.STREAM_SCAN_OVERLAP
        )
        committed_end = first_read - workspace.STREAM_SCAN_OVERLAP
        candidate_start = committed_end - 513
        line_start = candidate_start - len(assignment_prefix)
        payload = (
            b"x" * (line_start - 1)
            + b"\n"
            + assignment_prefix
            + candidate
            + b'"\nstate = ok\n'
            + b"x" * workspace.STREAM_SCAN_OVERLAP
        )
        self.assertGreater(len(payload), first_read)

        scan = workspace._stream_secret_scan(
            io.BytesIO(payload),
            size=len(payload),
            capture_blocking_candidates=True,
            _continue_after_blocking=True,
        )

        self.assertIsNone(scan.blocking_rule)
        self.assertEqual(
            scan.blocking_candidates,
            {candidate: {"openai-key"}},
        )

    def test_unsafe_long_provider_rhs_crosses_first_commit_and_blocks(self) -> None:
        candidate = b"sk-" + b"proj-" + b"B" * 508
        first_read = (
            workspace.MAX_SECRET_PREFIX_PROOF_BYTES + workspace.STREAM_SCAN_OVERLAP
        )
        committed_end = first_read - workspace.STREAM_SCAN_OVERLAP
        candidate_start = committed_end - 513
        assignment_prefix = b"api_" + b"token = "
        cases = (
            ("quoted", assignment_prefix + b'"', b'" + continued\n'),
            ("unquoted", assignment_prefix, b" \\" + b"\ncontinued\n"),
        )
        for label, assignment_prefix, continuation in cases:
            with self.subTest(case=label):
                line_start = candidate_start - len(assignment_prefix)
                payload = (
                    b"x" * (line_start - 1)
                    + b"\n"
                    + assignment_prefix
                    + candidate
                    + continuation
                    + b"x" * workspace.STREAM_SCAN_OVERLAP
                )
                self.assertGreater(len(payload), first_read)

                scan = workspace._stream_secret_scan(
                    io.BytesIO(payload),
                    size=len(payload),
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                )

                self.assertEqual(
                    scan.blocking_rule,
                    "generic-secret-assignment",
                )
                self.assertEqual(
                    scan.blocking_candidates,
                    {candidate: {"openai-key"}},
                )

    def test_unsafe_short_provider_rhs_crosses_stream_frontier_and_blocks(
        self,
    ) -> None:
        candidate = b"ghp_" + b"A" * 36
        assignment_prefix = b"api_" + b"token = "
        proof_bytes = 512
        overlap = 128
        committed_end = proof_bytes
        candidate_start = committed_end - len(candidate)
        line_start = candidate_start - len(assignment_prefix)
        payload = (
            b"x" * (line_start - 1)
            + b"\n"
            + assignment_prefix
            + candidate
            + b" \\"
            + b"\ncontinued\n"
            + b"x" * overlap
        )
        self.assertGreater(len(payload), proof_bytes + overlap)

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 256),
        ):
            scan = workspace._stream_secret_scan(
                io.BytesIO(payload),
                size=len(payload),
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )

        self.assertEqual(scan.blocking_rule, "generic-secret-assignment")
        self.assertEqual(
            scan.blocking_candidates,
            {candidate: {"github-token"}},
        )

    def test_extended_short_provider_value_crosses_stream_frontier(self) -> None:
        candidate = b"ghp_" + b"A" * 36
        complete_candidate = candidate + b"+alpha"
        assignment_prefix = b"api_" + b"token = "
        proof_bytes = 512
        overlap = 128
        committed_end = proof_bytes
        candidate_start = committed_end - len(candidate)
        line_start = candidate_start - len(assignment_prefix)
        payload = (
            b"x" * (line_start - 1)
            + b"\n"
            + assignment_prefix
            + complete_candidate
            + b"\nstate = ok\n"
            + b"x" * overlap
        )
        self.assertGreater(len(payload), proof_bytes + overlap)

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 256),
        ):
            scan = workspace._stream_secret_scan(
                io.BytesIO(payload),
                size=len(payload),
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )

        self.assertIsNone(scan.blocking_rule)
        self.assertEqual(
            scan.blocking_candidates[complete_candidate],
            {"generic-secret-assignment"},
        )

    def test_incomplete_quoted_short_provider_crosses_stream_frontier_and_blocks(
        self,
    ) -> None:
        candidate = b"ghp_" + b"A" * 36
        assignment_prefix = b"api_" + b'token = "'
        proof_bytes = 512
        overlap = 128
        committed_end = proof_bytes
        candidate_start = committed_end - len(candidate)
        line_start = candidate_start - len(assignment_prefix)
        payload = (
            b"x" * (line_start - 1)
            + b"\n"
            + assignment_prefix
            + candidate
            + b'\\\ncontinued"\n'
            + b"x" * overlap
        )
        self.assertGreater(len(payload), proof_bytes + overlap)

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 256),
        ):
            scan = workspace._stream_secret_scan(
                io.BytesIO(payload),
                size=len(payload),
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )

        self.assertEqual(scan.blocking_rule, "generic-secret-assignment")
        self.assertEqual(
            scan.blocking_candidates,
            {candidate: {"github-token"}},
        )

    def test_audit_scan_captures_after_a_blocker_across_stream_chunks(self) -> None:
        accepted = accepted_legacy_value(LEGACY_A, rule="generic-secret-assignment")
        blocking = assignment_bytes(b"password", b"UnknownSecretValueA9Z8Y7")
        later = assignment_bytes(b"refresh_token", LEGACY_A.encode("ascii"))
        first_read = (
            workspace.MAX_SECRET_PREFIX_PROOF_BYTES + workspace.STREAM_SCAN_OVERLAP
        )
        payload = (
            blocking + b"\n" + b"x" * (first_read + 128 - len(blocking)) + b"\n" + later
        )

        ordinary = workspace._stream_secret_scan(
            io.BytesIO(payload),
            size=len(payload),
            accepted_values=(accepted,),
            capture_accepted_candidates=True,
        )
        self.assertEqual(ordinary.blocking_rule, "generic-secret-assignment")
        self.assertFalse(ordinary.accepted_counts)

        audit = workspace._stream_secret_scan(
            io.BytesIO(payload),
            size=len(payload),
            accepted_values=(accepted,),
            capture_accepted_candidates=True,
            _continue_after_blocking=True,
        )
        self.assertEqual(audit.blocking_rule, "generic-secret-assignment")
        self.assertEqual(audit.accepted_counts[accepted], 1)
        self.assertEqual(audit.accepted_candidates[accepted], {accepted.value})

        no_prior_blocker = workspace._stream_secret_scan(
            io.BytesIO(b"\n" * (first_read + 128) + later),
            accepted_values=(accepted,),
            capture_accepted_candidates=True,
            _continue_after_blocking=True,
        )
        self.assertEqual(
            no_prior_blocker.blocking_rule,
            "generic-secret-assignment",
        )
        self.assertFalse(no_prior_blocker.accepted_counts)
        self.assertFalse(no_prior_blocker.accepted_candidates)

        capture_only = workspace._scan_secret_value(
            b"unproven prefix\n" + later,
            accepted_values=(accepted,),
            prefix_context_complete=False,
            capture_accepted_candidates=True,
            _continue_after_blocking=True,
            _capture_only_legacy_evidence=True,
        )
        self.assertEqual(
            capture_only.blocking_rule,
            "generic-secret-assignment",
        )
        self.assertEqual(capture_only.accepted_counts[accepted], 1)

        local_capture_lengths: list[int] = []
        original_quoted_acceptance = workspace._quoted_assignment_may_accept

        def recording_quoted_acceptance(value: bytes, **kwargs):
            if kwargs.get("assignment_start") == 0:
                local_capture_lengths.append(len(value))
            return original_quoted_acceptance(value, **kwargs)

        with mock.patch.object(
            workspace,
            "_quoted_assignment_may_accept",
            side_effect=recording_quoted_acceptance,
        ):
            bounded_capture_only = workspace._scan_secret_value(
                b"x" * 4096 + b"\n" + later + b'\nstate = "expired"\n' + b"x" * 4096,
                accepted_values=(accepted,),
                prefix_context_complete=False,
                capture_accepted_candidates=True,
                _continue_after_blocking=True,
                _capture_only_legacy_evidence=True,
            )
        self.assertEqual(
            bounded_capture_only.blocking_rule,
            "generic-secret-assignment",
        )
        self.assertEqual(bounded_capture_only.accepted_counts[accepted], 1)
        self.assertTrue(local_capture_lengths)
        self.assertLessEqual(
            max(local_capture_lengths),
            len(later) + workspace.MAX_SECRET_ASSIGNMENT_TRAILING_BYTES + 1,
        )

        wrapper_capture_only = workspace._scan_secret_value(
            b"configure(\n" + later,
            accepted_values=(accepted,),
            prefix_context_complete=False,
            capture_accepted_candidates=True,
            _continue_after_blocking=True,
            _capture_only_legacy_evidence=True,
        )
        self.assertEqual(
            wrapper_capture_only.blocking_rule,
            "generic-secret-assignment",
        )
        self.assertEqual(wrapper_capture_only.accepted_counts[accepted], 1)

        reduced_capture_only = workspace._scan_secret_value(
            b"unproven prefix\n" + later,
            accepted_values=(accepted,),
            reduced_secret_values=frozenset((accepted.value,)),
            prefix_context_complete=False,
            capture_accepted_candidates=True,
            _continue_after_blocking=True,
            _capture_only_legacy_evidence=True,
        )
        self.assertEqual(
            reduced_capture_only.blocking_rule,
            "generic-secret-assignment",
        )
        self.assertEqual(reduced_capture_only.accepted_counts[accepted], 1)

        authoring = self.accepted[0]
        authoring_capture_only = workspace._scan_secret_value(
            b"unproven prefix\n" + assignment_bytes(b"access_token", authoring.value),
            accepted_values=(authoring,),
            prefix_context_complete=False,
            capture_accepted_candidates=True,
            _continue_after_blocking=True,
            _capture_only_legacy_evidence=True,
        )
        self.assertEqual(
            authoring_capture_only.blocking_rule,
            "generic-secret-assignment",
        )
        self.assertFalse(authoring_capture_only.accepted_counts)

        incomplete_capture_only = workspace._scan_secret_value(
            b"unproven prefix\n" + later[:-1],
            accepted_values=(accepted,),
            prefix_context_complete=False,
            suffix_context_complete=False,
            capture_accepted_candidates=True,
            _continue_after_blocking=True,
            _capture_only_legacy_evidence=True,
        )
        self.assertIsNone(incomplete_capture_only.blocking_rule)
        self.assertFalse(incomplete_capture_only.accepted_counts)

        unsafe = workspace._scan_secret_value(
            assignment_bytes(b"refresh_token", accepted.value) + b' + "adjacent"\n',
            accepted_values=(accepted,),
            capture_accepted_candidates=True,
            _continue_after_blocking=True,
        )
        self.assertEqual(unsafe.blocking_rule, "generic-secret-assignment")
        self.assertFalse(unsafe.accepted_counts)
        self.assertFalse(unsafe.accepted_candidates)

        unsafe_capture_only = workspace._scan_secret_value(
            b"unproven prefix\n"
            + assignment_bytes(b"refresh_token", accepted.value)
            + b' + "adjacent"\n',
            accepted_values=(accepted,),
            prefix_context_complete=False,
            capture_accepted_candidates=True,
            _continue_after_blocking=True,
            _capture_only_legacy_evidence=True,
        )
        self.assertEqual(
            unsafe_capture_only.blocking_rule,
            "generic-secret-assignment",
        )
        self.assertFalse(unsafe_capture_only.accepted_counts)

    def test_oversized_provider_token_crossing_stream_boundary_is_blocked(self) -> None:
        boundary = 1024 * 1024
        token_start = boundary - (workspace.STREAM_SCAN_OVERLAP * 3)
        payload = (
            b"x" * (token_start - 1)
            + b"\n"
            + b"sk-"
            + b"D" * (workspace.STREAM_SCAN_OVERLAP * 3)
            + b"\n"
        )
        self.assertEqual(
            workspace._stream_secret_rule(io.BytesIO(payload), size=len(payload)),
            "openai-key",
        )

    def test_oversized_provider_patterns_have_bounded_prefix_matches(self) -> None:
        cases = (
            ("anthropic-key", b"sk-ant-", b"A", 4096),
            ("openai-key", b"sk-proj-", b"B", 4096),
            ("github-token", b"ghp_", b"C", 4096),
            ("github-token", b"github_pat_", b"D", 513),
            ("gitlab-token", b"glpat-", b"E", 4096),
            ("google-api-key", b"AIza", b"F", 4096),
            ("pypi-token", b"pypi-", b"G", 4096),
            ("slack-token", b"xoxb-", b"H", 4096),
            ("stripe-live-key", b"sk_live_", b"I", 4096),
        )
        for expected_rule, prefix, alphabet, body_length in cases:
            with self.subTest(rule=expected_rule):
                scan = workspace._scan_secret_value(
                    prefix + alphabet * body_length,
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                )
                self.assertEqual(scan.blocking_rule, expected_rule)
                self.assertEqual(len(scan.blocking_candidates), 0)

    def test_oversized_jwt_segments_are_blocked(self) -> None:
        normal = b"A" * 12
        oversized = b"B" * 2049
        cases = (
            b"eyJ" + oversized + b"." + normal + b"." + normal,
            b"eyJ" + normal + b"." + oversized + b"." + normal,
            b"eyJ" + normal + b"." + normal + b"." + oversized,
        )
        for index, value in enumerate(cases, start=1):
            with self.subTest(segment=index):
                self.assertEqual(
                    workspace._scan_secret_value(value).blocking_rule,
                    "jwt",
                )

    def test_jwt_base64url_suffix_crosses_stream_commit_boundary(self) -> None:
        shorter = reduction_secret("jwt")
        candidate = shorter + b"-"
        proof_bytes = 512
        overlap = 128
        committed_end = proof_bytes
        candidate_start = committed_end - len(shorter)
        payload = (
            b"x" * (candidate_start - 1) + b"\n" + candidate + b"!\n" + b"x" * overlap
        )
        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 256),
        ):
            scan = workspace._stream_secret_scan(
                io.BytesIO(payload),
                size=len(payload),
                capture_blocking_candidates=True,
                _continue_after_blocking=True,
            )

        self.assertIsNone(scan.blocking_rule)
        self.assertEqual(scan.blocking_candidates, {candidate: {"jwt"}})
        self.assertNotIn(shorter, scan.blocking_candidates)

    def test_jwe_uses_the_complete_five_segment_candidate(self) -> None:
        shared_prefix = b"eyJ" + b"A" * 12 + b".." + b"C" * 12
        candidate = shared_prefix + b"." + b"D" * 12 + b"." + b"E" * 12

        scan = workspace._scan_secret_value(
            candidate,
            capture_blocking_candidates=True,
            _continue_after_blocking=True,
        )

        self.assertIsNone(scan.blocking_rule)
        self.assertEqual(scan.blocking_candidates, {candidate: {"jwt"}})
        self.assertNotIn(shared_prefix, scan.blocking_candidates)

        malformed_candidates = (
            shared_prefix + b"." + b"D" * 12,
            candidate + b"." + b"F" * 12,
        )
        for malformed in malformed_candidates:
            with self.subTest(segments=malformed.count(b".") + 1):
                malformed_scan = workspace._scan_secret_value(
                    malformed,
                    capture_blocking_candidates=True,
                    _continue_after_blocking=True,
                )
                self.assertEqual(malformed_scan.blocking_rule, "jwt")
                self.assertFalse(malformed_scan.blocking_candidates)

    def test_dense_jwe_scan_indexes_specific_spans_once(self) -> None:
        class IterationCountingSet(set[tuple[int, int, bytes]]):
            def __init__(self) -> None:
                super().__init__()
                self.iterations = 0

            def __iter__(self):
                self.iterations += 1
                return super().__iter__()

        candidate_count = 256
        candidates = tuple(
            b"eyJ"
            + b"A" * 12
            + b".."
            + f"{index:012x}".encode("ascii")
            + b"."
            + b"D" * 12
            + b"."
            + b"E" * 12
            for index in range(candidate_count)
        )
        spans = IterationCountingSet()

        events = tuple(
            workspace._iter_secret_events(
                b"\n".join(candidates),
                _specific_spans=spans,
            )
        )

        self.assertEqual(spans.iterations, 1)
        self.assertEqual(len(spans), candidate_count)
        self.assertEqual(
            sum(
                rule == "jwt" and candidate is not None
                for rule, candidate, *_ in events
            ),
            candidate_count,
        )

    def test_oversized_assignment_gap_crossing_stream_boundary_is_blocked(self) -> None:
        boundary = 1024 * 1024
        token_start = boundary - (workspace.STREAM_SCAN_OVERLAP * 3)
        prefix = b"x" * (token_start - 1) + b"\n"
        gap = b" " * (workspace.STREAM_SCAN_OVERLAP * 3)
        cases = (
            (
                "generic-secret-assignment",
                b"password" + gap + b' = "' + HIGH_ENTROPY + b'"\n',
            ),
            (
                "aws-secret-key",
                b"aws_secret_access_key" + gap + b" = " + b"A" * 40 + b"\n",
            ),
        )
        for expected_rule, assignment in cases:
            with self.subTest(rule=expected_rule):
                payload = prefix + assignment
                self.assertEqual(
                    workspace._stream_secret_rule(
                        io.BytesIO(payload),
                        size=len(payload),
                    ),
                    expected_rule,
                )


class CatalogValidationTest(unittest.TestCase):
    def parse(self, payload: object):
        return synthetic_tokens.parse_catalog_bytes(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )

    def test_duplicate_keys_fail_closed(self) -> None:
        encoded = synthetic_tokens.CATALOG_PATH.read_bytes()
        duplicate = encoded.replace(
            b'"schema_version": 1,',
            b'"schema_version": 1, "schema_version": 1,',
            1,
        )
        with self.assertRaisesRegex(ReviewError, "duplicate key"):
            synthetic_tokens.parse_catalog_bytes(duplicate)

    def test_malformed_schema_ascii_control_and_rule_fail_closed(self) -> None:
        cases: dict[str, dict[str, object]] = {}
        schema = catalog_payload()
        schema["schema_version"] = True
        cases["schema"] = schema
        unicode_value = catalog_payload()
        unicode_value["authoring_pool"]["tokens"][0]["value"] = (
            "synthetic_\N{CYRILLIC SMALL LETTER O}_credential"
        )
        cases["unicode"] = unicode_value
        control = catalog_payload()
        control["authoring_pool"]["tokens"][0]["value"] = "synthetic credential value"
        cases["control"] = control
        for label, value in (
            ("double-quote", 'synthetic_value_with_"_quote'),
            ("single-quote", "synthetic_value_with_'_quote"),
            ("backslash", r"synthetic_value_with_\_escape"),
            ("parenthesis", "synthetic_value_with_(delimiter"),
            ("backtick", "synthetic_value_with_`_delimiter"),
            ("pipe", "synthetic_value_with_|_delimiter"),
            ("comma", "synthetic_value_with_,_delimiter"),
        ):
            malformed = catalog_payload()
            malformed["authoring_pool"]["tokens"][0]["value"] = value
            cases[label] = malformed
        for disallowed_rule in ("github-token", "jwt"):
            rule = catalog_payload()
            rule["authoring_pool"]["tokens"][0]["rule"] = disallowed_rule
            cases[f"authoring-rule-{disallowed_rule}"] = rule
        extra = catalog_payload()
        extra["unexpected"] = True
        cases["extra-field"] = extra

        for label, payload in cases.items():
            with self.subTest(case=label), self.assertRaises(ReviewError):
                self.parse(payload)

    def test_authoring_entries_must_pass_the_real_scanner_contract(self) -> None:
        cases = (
            ("placeholder", "placeholder_test_token"),
            ("provider", "ghp_" + "A" * 36),
            ("unquoted-invisible", "lowercaseauthoringvalue"),
        )
        for label, value in cases:
            payload = catalog_payload()
            payload["authoring_pool"]["tokens"][0]["value"] = value
            catalog = self.parse(payload)
            with (
                self.subTest(case=label),
                self.assertRaisesRegex(ReviewError, "not captured exactly once"),
            ):
                workspace.validate_authoring_catalog_scanner_contract(catalog)

    def test_current_authoring_pool_passes_the_real_scanner_contract(self) -> None:
        workspace.validate_authoring_catalog_scanner_contract(
            synthetic_tokens.load_catalog()
        )

    def test_authoring_values_cannot_overlap_public_metadata(self) -> None:
        raw_value = "synthetic-token-123"
        own_id = catalog_payload()
        own_id["authoring_pool"]["tokens"][0].update(
            {"id": raw_value, "value": raw_value}
        )
        pool_version = catalog_payload()
        pool_version["authoring_pool"]["version"] = f"pool-{raw_value}"
        pool_version["authoring_pool"]["tokens"][0]["value"] = raw_value
        other_id = catalog_payload()
        other_id["authoring_pool"]["tokens"][0]["value"] = raw_value
        other_id["authoring_pool"]["tokens"][1]["id"] = f"other-{raw_value}"
        legacy_metadata = catalog_payload()
        legacy_metadata["authoring_pool"]["tokens"][0]["value"] = raw_value
        legacy_metadata["legacy_exemptions"] = [
            {
                "id": "historical-fixtures",
                "repository": f"example/{raw_value}",
                "verified_master_tip": "a" * 40,
                "match": "non-increasing-global-count",
                "values": [
                    {
                        "id": "historical-1",
                        "rule": "generic-secret-assignment",
                        "value_base64": legacy_value_base64(LEGACY_A),
                        "containing_commit": "b" * 40,
                        "source_occurrences": 1,
                    }
                ],
            }
        ]

        for label, payload in (
            ("own-id", own_id),
            ("pool-version", pool_version),
            ("other-id", other_id),
            ("legacy-metadata", legacy_metadata),
        ):
            with self.subTest(case=label):
                with self.assertRaisesRegex(
                    ReviewError,
                    "exact value overlaps public metadata",
                ) as caught:
                    self.parse(payload)
                self.assertNotIn(raw_value, str(caught.exception))

    def test_duplicate_ids_values_and_overlaps_fail_closed(self) -> None:
        duplicate_id = catalog_payload()
        duplicate_id["authoring_pool"]["tokens"][1]["id"] = duplicate_id[
            "authoring_pool"
        ]["tokens"][0]["id"]
        duplicate_value = catalog_payload()
        duplicate_value["authoring_pool"]["tokens"][1]["value"] = duplicate_value[
            "authoring_pool"
        ]["tokens"][0]["value"]
        overlap = catalog_payload()
        overlap["authoring_pool"]["tokens"][0]["value"] = "synthetic_fixture_value"
        overlap["authoring_pool"]["tokens"][1]["value"] = (
            "synthetic_fixture_value_suffix"
        )
        for label, payload in (
            ("duplicate-id", duplicate_id),
            ("duplicate-value", duplicate_value),
            ("overlap", overlap),
        ):
            with self.subTest(case=label), self.assertRaises(ReviewError):
                self.parse(payload)

    def test_legacy_overlaps_must_share_one_selected_envelope(self) -> None:
        payload = catalog_payload()
        longer = LEGACY_A + "Suffix"
        payload["legacy_exemptions"] = [
            {
                "id": exemption_id,
                "repository": "example/project",
                "verified_master_tip": "a" * 40,
                "match": "non-increasing-global-count",
                "values": [
                    {
                        "id": token_id,
                        "rule": "generic-secret-assignment",
                        "value_base64": legacy_value_base64(value),
                        "containing_commit": "b" * 40,
                        "source_occurrences": 1,
                    }
                ],
            }
            for exemption_id, token_id, value in (
                ("historical-short", "legacy-short", LEGACY_A),
                ("historical-long", "legacy-long", longer),
            )
        ]
        with self.assertRaisesRegex(ReviewError, "overlapping values"):
            self.parse(payload)

    def test_malformed_and_duplicate_legacy_entries_fail_closed(self) -> None:
        payload = catalog_payload()
        entry = {
            "id": "legacy-a",
            "rule": "generic-secret-assignment",
            "value_base64": legacy_value_base64(LEGACY_A),
            "containing_commit": "b" * 40,
            "source_occurrences": 1,
        }
        envelope = {
            "id": "historical-fixtures",
            "repository": "example/project",
            "verified_master_tip": "a" * 40,
            "match": "non-increasing-global-count",
            "values": [entry, {**entry, "id": "legacy-b"}],
        }
        payload["legacy_exemptions"] = [envelope]
        with self.assertRaisesRegex(ReviewError, "duplicate value"):
            self.parse(payload)

        cross_rule_duplicate = catalog_payload()
        cross_rule_duplicate["legacy_exemptions"] = [
            {
                **envelope,
                "values": [
                    entry,
                    {**entry, "id": "legacy-b", "rule": "github-token"},
                ],
            }
        ]
        with self.assertRaisesRegex(ReviewError, "duplicate value"):
            self.parse(cross_rule_duplicate)

        authoring_collision = catalog_payload()
        authoring_value = authoring_collision["authoring_pool"]["tokens"][0]["value"]
        authoring_collision["legacy_exemptions"] = [
            {
                **envelope,
                "values": [
                    {
                        **entry,
                        "rule": "github-token",
                        "value_base64": legacy_value_base64(authoring_value),
                    }
                ],
            }
        ]
        with self.assertRaisesRegex(ReviewError, "duplicate value"):
            self.parse(authoring_collision)

        storage_raw = "jgajgajgajgajgajga"
        storage_value = legacy_value_base64(storage_raw)
        storage_metadata_collision = catalog_payload()
        storage_metadata_collision["legacy_exemptions"] = [
            {
                **envelope,
                "values": [
                    {
                        **entry,
                        "id": storage_value,
                        "value_base64": storage_value,
                    }
                ],
            }
        ]
        with self.assertRaisesRegex(
            ReviewError,
            "storage encoding overlaps public",
        ) as metadata_caught:
            self.parse(storage_metadata_collision)
        self.assertNotIn(storage_value, str(metadata_caught.exception))

        storage_authoring_collision = catalog_payload()
        storage_authoring_collision["authoring_pool"]["tokens"][0]["value"] = (
            storage_value
        )
        storage_authoring_collision["legacy_exemptions"] = [
            {
                **envelope,
                "values": [
                    {
                        **entry,
                        "value_base64": legacy_value_base64(storage_raw),
                    }
                ],
            }
        ]
        with self.assertRaisesRegex(
            ReviewError,
            "storage encoding overlaps an exact",
        ) as exact_caught:
            self.parse(storage_authoring_collision)
        self.assertNotIn(storage_value, str(exact_caught.exception))

        for field, value in (
            ("value_base64", "not-canonical-base64"),
            (
                "value_base64",
                legacy_value_base64(
                    LEGACY_A.replace(
                        "A",
                        "\N{LATIN CAPITAL LETTER A WITH RING ABOVE}",
                        1,
                    )
                ),
            ),
            ("source_occurrences", 0),
            ("rule", "aws-access-key"),
        ):
            malformed = catalog_payload()
            malformed_entry = {**entry, field: value}
            malformed["legacy_exemptions"] = [{**envelope, "values": [malformed_entry]}]
            with self.subTest(field=field), self.assertRaises(ReviewError):
                self.parse(malformed)

    def test_legacy_values_accept_only_bounded_printable_ascii(self) -> None:
        catalog = legacy_catalog(values=(LEGACY_PRINTABLE,))
        value = catalog.legacy_exemption("historical-fixtures").values[0]
        self.assertEqual(value.value, LEGACY_PRINTABLE.encode("ascii"))

        authoring = catalog_payload()
        authoring["authoring_pool"]["tokens"][0]["value"] = LEGACY_PRINTABLE
        with self.assertRaisesRegex(ReviewError, "visible ASCII"):
            self.parse(authoring)

        for label, candidate in (
            ("short", "x" * 15),
            ("long", "x" * 513),
            ("tab", "Historical\tFixtureValueA9Z8Y7"),
            ("carriage-return", "Historical\rFixtureValueA9Z8Y7"),
            ("newline", "Historical\nFixtureValueA9Z8Y7"),
            ("null", "Historical\x00FixtureValueA9Z8Y7"),
            ("unit-separator", "Historical\x1fFixtureValueA9Z8Y7"),
            ("delete", "Historical\x7fFixtureValueA9Z8Y7"),
            ("single-quote", "Historical'FixtureValueA9Z8Y7"),
            ("double-quote", 'Historical"FixtureValueA9Z8Y7'),
        ):
            with self.subTest(case=label), self.assertRaises(ReviewError):
                legacy_catalog(values=(candidate,))

    def test_jwt_is_not_an_allowed_legacy_or_authoring_rule(self) -> None:
        with self.assertRaisesRegex(ReviewError, "rule is not allowed"):
            legacy_catalog(values=(JWT_LEGACY,), rule="jwt")

        authoring = catalog_payload()
        authoring["authoring_pool"]["tokens"][0]["rule"] = "jwt"
        with self.assertRaisesRegex(ReviewError, "rule is not allowed"):
            self.parse(authoring)

    def test_secure_loader_rejects_symlink_hardlink_fifo_and_writable_file(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            original = synthetic_tokens.CATALOG_PATH.read_bytes()
            target = root / "target.json"
            target.write_bytes(original)
            target.chmod(0o600)

            symlink = root / "symlink.json"
            symlink.symlink_to(target)
            hardlink = root / "hardlink.json"
            os.link(target, hardlink)
            fifo = root / "catalog.fifo"
            os.mkfifo(fifo, mode=0o600)
            writable = root / "writable.json"
            writable.write_bytes(original)
            writable.chmod(0o620)

            for label, path in (
                ("symlink", symlink),
                ("hardlink", target),
                ("fifo", fifo),
                ("writable", writable),
            ):
                with (
                    self.subTest(file_type=label),
                    mock.patch.object(synthetic_tokens, "CATALOG_PATH", path),
                    self.assertRaises(ReviewError),
                ):
                    synthetic_tokens.load_catalog()


class SyntheticTokenCliTest(unittest.TestCase):
    def run_cli(self, *args: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            returncode = cli.main(["synthetic-tokens", *args])
        return returncode, stdout.getvalue(), stderr.getvalue()

    def test_validate_and_list_return_metadata_without_raw_values(self) -> None:
        returncode, output, error = self.run_cli("validate")
        self.assertEqual((returncode, error), (0, ""))
        self.assertEqual(json.loads(output)["status"], "valid")

        returncode, output, error = self.run_cli("list", "--json")
        self.assertEqual((returncode, error), (0, ""))
        payload = json.loads(output)
        catalog = synthetic_tokens.load_catalog()
        self.assertEqual(set(payload), {"pool_version", "tokens"})
        self.assertEqual(payload["pool_version"], catalog.pool_version)
        self.assertEqual(len(payload["tokens"]), len(catalog.authoring_tokens))
        self.assertEqual(
            [token["id"] for token in payload["tokens"]],
            sorted(token["id"] for token in payload["tokens"]),
        )
        self.assertTrue(
            all(
                set(token) == {"id", "role", "rule", "state", "value_sha256"}
                and re.fullmatch(r"[0-9a-f]{64}", token["value_sha256"])
                for token in payload["tokens"]
            )
        )
        self.assertTrue(all("value" not in token for token in payload["tokens"]))
        output_bytes = output.encode("utf-8")
        self.assertFalse(
            any(raw.encode("ascii") in output_bytes for raw in AUTHORING_VALUES)
        )

    def test_thin_skill_templates_resolve_through_stable_metadata(self) -> None:
        returncode, output, error = self.run_cli("list", "--json")
        self.assertEqual((returncode, error), (0, ""))
        tokens = json.loads(output)["tokens"]
        requirements = {
            "SYNTHETIC_ACCESS_TOKEN": ("access", "active"),
            "SYNTHETIC_REFRESH_TOKEN": ("refresh", "active"),
            "SYNTHETIC_ID_TOKEN": ("id", "active"),
            "SYNTHETIC_ACTIVE_ACCESS_TOKEN": ("access", "active"),
            "SYNTHETIC_EXPIRED_ACCESS_TOKEN": ("access", "expired"),
            "SYNTHETIC_ACTIVE_REFRESH_TOKEN": ("refresh", "active"),
            "SYNTHETIC_CONSUMED_REFRESH_TOKEN": ("refresh", "consumed"),
            "SYNTHETIC_API_KEY": ("api-key", "active"),
            "SYNTHETIC_BEARER_TOKEN": ("bearer", "active"),
        }
        template = (THIN_SKILL_ROOT / "references/fixture-templates.md").read_text(
            encoding="utf-8"
        )
        placeholders = set(re.findall(r"<([A-Z0-9_]+)>", template))
        self.assertEqual(placeholders, set(requirements))

        selections: dict[str, str] = {}
        for placeholder, (role, state) in requirements.items():
            compatible_ids = sorted(
                token["id"]
                for token in tokens
                if token["role"] == role and token["state"] == state
            )
            self.assertTrue(compatible_ids, placeholder)
            selections[placeholder] = compatible_ids[0]
        self.assertEqual(len(selections), len(requirements))
        for distinct_group in (
            (
                "SYNTHETIC_ACCESS_TOKEN",
                "SYNTHETIC_REFRESH_TOKEN",
                "SYNTHETIC_ID_TOKEN",
            ),
            (
                "SYNTHETIC_ACTIVE_ACCESS_TOKEN",
                "SYNTHETIC_EXPIRED_ACCESS_TOKEN",
                "SYNTHETIC_ACTIVE_REFRESH_TOKEN",
                "SYNTHETIC_CONSUMED_REFRESH_TOKEN",
            ),
            ("SYNTHETIC_API_KEY", "SYNTHETIC_BEARER_TOKEN"),
        ):
            self.assertEqual(
                len({selections[item] for item in distinct_group}),
                len(distinct_group),
            )
        self.assertNotIn("SYNTHETIC_SECONDARY_API_KEY", template)

    def test_validate_rejects_an_authoring_value_the_scanner_cannot_accept(
        self,
    ) -> None:
        payload = catalog_payload()
        payload["authoring_pool"]["tokens"][0]["value"] = "placeholder_test_token"
        catalog = synthetic_tokens.parse_catalog_bytes(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        with mock.patch.object(cli, "load_catalog", return_value=catalog):
            returncode, output, error = self.run_cli("validate")
        self.assertEqual(returncode, 2)
        self.assertEqual(output, "")
        self.assertIn("not captured exactly once", error)
        self.assertNotIn("placeholder_test_token", error)

    def test_get_returns_only_the_explicitly_selected_raw_value(self) -> None:
        catalog = synthetic_tokens.load_catalog()
        selected = sorted(catalog.authoring_tokens, key=lambda token: token.identifier)[
            0
        ]
        returncode, output, error = self.run_cli(
            "get",
            selected.identifier,
            "--json",
        )
        self.assertEqual((returncode, error), (0, ""))
        payload = json.loads(output)
        returned_value = payload["token"]["value"].encode("ascii")
        self.assertEqual(
            hashlib.sha256(returned_value).hexdigest(),
            selected.value_sha256,
        )
        output_bytes = output.encode("utf-8")
        self.assertFalse(
            any(
                token.value in output_bytes
                for token in catalog.authoring_tokens
                if token.identifier != selected.identifier
            )
        )

    def test_list_exemptions_and_unknown_get(self) -> None:
        returncode, output, error = self.run_cli("list-exemptions", "--json")
        self.assertEqual((returncode, error), (0, ""))
        catalog = synthetic_tokens.load_catalog()
        exemptions = json.loads(output)["exemptions"]
        self.assertEqual(
            [item["id"] for item in exemptions],
            sorted(item.identifier for item in catalog.legacy_exemptions),
        )
        output_bytes = output.encode("utf-8")
        catalog_legacy_values = synthetic_tokens.accepted_legacy_values(
            catalog,
            catalog.legacy_exemptions,
        )
        self.assertFalse(
            any(
                descriptor.value is not None
                and (
                    descriptor.value in output_bytes
                    or base64.b64encode(descriptor.value) in output_bytes
                )
                for descriptor in catalog_legacy_values
            )
        )

        catalog = legacy_catalog(values=(LEGACY_A,))
        with mock.patch.object(cli, "load_catalog", return_value=catalog):
            returncode, output, error = self.run_cli("list-exemptions", "--json")
        self.assertEqual((returncode, error), (0, ""))
        value_metadata = json.loads(output)["exemptions"][0]["values"][0]
        self.assertEqual(value_metadata["value_length"], len(LEGACY_A))
        self.assertIn("value_sha256", value_metadata)
        self.assertNotIn("value", value_metadata)
        self.assertNotIn(LEGACY_A, output)
        self.assertNotIn(legacy_value_base64(LEGACY_A), output)

        returncode, output, error = self.run_cli("get", "missing", "--json")
        self.assertEqual(returncode, 2)
        self.assertEqual(output, "")
        self.assertIn("unknown synthetic authoring token", error)


class SyntheticWorkspaceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.reviews: list[workspace.ReviewWorkspace] = []

    def tearDown(self) -> None:
        for review in self.reviews:
            if review.workspace_root.exists():
                workspace.cleanup_workspace(review, keep_container=False)
        self.temporary.cleanup()

    def new_repo(self, files: dict[str, str]) -> tuple[pathlib.Path, str]:
        repo = self.root / f"repo-{len(list(self.root.glob('repo-*')))}"
        repo.mkdir()
        subprocess.run(
            ("git", "init", "-b", "master", str(repo)),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        git(repo, "config", "user.name", "Synthetic Token Test")
        git(repo, "config", "user.email", "synthetic@example.com")
        git(repo, "config", "commit.gpgsign", "false")
        (repo / ".gitignore").write_text(".codex-tmp/\n", encoding="utf-8")
        for relative, value in files.items():
            path = repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value, encoding="utf-8")
        git(repo, "add", ".")
        git(repo, "commit", "-m", "Base")
        return repo, git(repo, "rev-parse", "HEAD")

    def commit(self, repo: pathlib.Path, message: str = "Head") -> str:
        git(repo, "add", "-A")
        git(repo, "commit", "-m", message)
        return git(repo, "rev-parse", "HEAD")

    def prepare(
        self,
        *,
        repo: pathlib.Path,
        base: str,
        head: str,
        catalog=None,
        exemptions: tuple[str, ...] = (),
        prompt_override: pathlib.Path | None = None,
    ) -> workspace.ReviewWorkspace:
        captured: list[workspace.ReviewWorkspace] = []
        catalog = catalog or synthetic_tokens.load_catalog()
        with mock.patch.object(workspace, "load_catalog", return_value=catalog):
            review = workspace.prepare_workspace(
                repo=repo,
                base_ref=base,
                head_ref=head,
                synthetic_secret_exemptions=exemptions,
                prompt_override=prompt_override,
                ownership_handoff=captured.append,
            )
        self.assertEqual(captured, [review])
        self.reviews.append(review)
        return review

    def validate(self, review: workspace.ReviewWorkspace, *, catalog=None):
        catalog = catalog or synthetic_tokens.load_catalog()
        with mock.patch.object(workspace, "load_catalog", return_value=catalog):
            return workspace.validate_external_workspace(review)

    def test_authoring_value_passes_and_evidence_never_contains_raw_value(self) -> None:
        repo, base = self.new_repo({"README.md": "base\n"})
        (repo / "fixture.cfg").write_text(
            assignment_text("access_token", AUTHORING_VALUES[0]),
            encoding="utf-8",
        )
        head = self.commit(repo)
        review = self.prepare(repo=repo, base=base, head=head)
        evidence = self.validate(review)
        encoded = json.dumps(evidence, sort_keys=True)
        self.assertFalse(AUTHORING_VALUES[0] in encoded)
        accepted = evidence["synthetic_tokens"]["accepted"]
        self.assertTrue(accepted)
        self.assertTrue(all("value_sha256" in entry for entry in accepted))
        self.assertTrue(any(entry["token_id"] == "access-a" for entry in accepted))

    def test_prepared_range_allows_only_strict_secret_count_reductions(self) -> None:
        for rule in (
            "generic-secret-assignment",
            "jwt",
            "github-token",
        ):
            for transition, head_count in (("delete", 0), ("partial", 1)):
                with self.subTest(rule=rule, transition=transition):
                    fixture = reduction_fixture(rule)
                    repo, base = self.new_repo({"fixture.cfg": fixture * 2})
                    if head_count:
                        (repo / "fixture.cfg").write_text(
                            fixture,
                            encoding="utf-8",
                        )
                    else:
                        (repo / "fixture.cfg").unlink()
                    head = self.commit(repo)

                    review = self.prepare(repo=repo, base=base, head=head)
                    manifest_path = (
                        review.workspace_root
                        / ".codex-review"
                        / workspace.SYNTHETIC_MANIFEST_NAME
                    )
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    self.assertEqual(manifest["schema_version"], 4)
                    self.assertEqual(len(manifest["secret_reductions"]), 1)
                    reduction = manifest["secret_reductions"][0]
                    self.assertEqual(
                        (reduction["base_count"], reduction["head_count"]),
                        (2, head_count),
                    )
                    self.assertEqual(reduction["rules"], [rule])

                    evidence = self.validate(review)
                    self.assertEqual(
                        evidence["synthetic_tokens"]["secret_reductions"],
                        manifest["secret_reductions"],
                    )

    def test_changed_path_public_evidence_contains_only_digests(self) -> None:
        fixture = reduction_fixture("generic-secret-assignment")
        repo, base = self.new_repo({"fixture.cfg": fixture * 2})
        (repo / "fixture.cfg").write_text(fixture, encoding="utf-8")
        head = self.commit(repo)

        review = self.prepare(repo=repo, base=base, head=head)
        raw_path = b"fixture.cfg"
        public_paths = (
            review.workspace_root
            / ".codex-review"
            / workspace.CHANGED_PATH_DIGESTS_NAME
        ).read_bytes()
        private_paths = (
            review.container_dir / workspace.PRIVATE_CHANGED_PATHS_NAME
        ).read_bytes()

        self.assertEqual(
            public_paths,
            hashlib.sha256(raw_path).hexdigest().encode("ascii") + b"\0",
        )
        self.assertNotIn(raw_path, public_paths)
        self.assertEqual(private_paths, raw_path + b"\0")
        self.validate(review)

    def test_dynamic_secret_in_head_path_blocks_before_handoff(self) -> None:
        raw_value = reduction_secret("generic-secret-assignment").decode("ascii")
        fixture = assignment_text("password", raw_value)
        cases = (
            ("raw", raw_value),
            (
                "storage",
                base64.b64encode(raw_value.encode("ascii")).decode("ascii"),
            ),
        )
        for label, path_value in cases:
            with self.subTest(case=label):
                repo, base = self.new_repo({"fixture.cfg": fixture * 2})
                (repo / "fixture.cfg").rename(repo / path_value)
                (repo / path_value).write_text(fixture, encoding="utf-8")
                head = self.commit(repo)

                with self.assertRaisesRegex(
                    ReviewError,
                    "frozen head paths",
                ) as caught:
                    self.prepare(repo=repo, base=base, head=head)
                self.assertNotIn(raw_value, str(caught.exception))
                self.assertNotIn(path_value, str(caught.exception))

    def test_overlong_dynamic_secret_path_blocks_before_materialization(self) -> None:
        raw_value = reduction_secret("generic-secret-assignment").decode("ascii")
        fixture = assignment_text("password", raw_value)
        repo, base = self.new_repo(
            {
                "secret-a.cfg": fixture,
                "secret-b.cfg": fixture,
            }
        )
        secret_blob = git(repo, "rev-parse", f"{base}:secret-a.cfg")
        overlong_path = raw_value + "-" + "x" * (300 - len(raw_value) - 1)
        self.assertGreater(len(os.fsencode(overlong_path)), 255)
        git(repo, "read-tree", base)
        git(repo, "update-index", "--force-remove", "secret-a.cfg", "secret-b.cfg")
        git(
            repo,
            "update-index",
            "--add",
            "--cacheinfo",
            "100644",
            secret_blob,
            overlong_path,
        )
        tree = git(repo, "write-tree")
        head = git(repo, "commit-tree", tree, "-p", base, "-m", "Head")
        handoffs: list[workspace.ReviewWorkspace] = []
        materialize_frozen_tree = workspace._materialize_frozen_tree

        with (
            mock.patch.object(
                workspace,
                "_materialize_frozen_tree",
                wraps=materialize_frozen_tree,
            ) as materialize,
            self.assertRaisesRegex(ReviewError, "frozen head paths") as caught,
        ):
            workspace.prepare_workspace(
                repo=repo,
                base_ref=base,
                head_ref=head,
                ownership_handoff=handoffs.append,
            )

        materialize.assert_not_called()
        self.assertEqual(handoffs, [])
        self.assertNotIn(raw_value, str(caught.exception))
        self.assertNotIn(overlong_path, str(caught.exception))

    def test_materialized_head_path_cannot_add_a_reduced_dynamic_secret(self) -> None:
        raw_value = reduction_secret("generic-secret-assignment").decode("ascii")
        fixture = assignment_text("password", raw_value)
        repo, base = self.new_repo({"fixture.cfg": fixture * 2})
        (repo / "fixture.cfg").write_text(fixture, encoding="utf-8")
        head = self.commit(repo)
        review = self.prepare(repo=repo, base=base, head=head)
        (review.workspace_root / "fixture.cfg").rename(
            review.workspace_root / raw_value
        )

        with self.assertRaisesRegex(
            ReviewError,
            "secret-reduction-value",
        ) as caught:
            self.validate(review)
        self.assertNotIn(raw_value, str(caught.exception))

    def test_deleted_dynamic_secret_path_remains_reviewable_in_raw_diff(self) -> None:
        raw_value = reduction_secret("generic-secret-assignment").decode("ascii")
        fixture = assignment_text("password", raw_value)
        repo, base = self.new_repo({raw_value: fixture * 2})
        (repo / raw_value).unlink()
        head = self.commit(repo)

        review = self.prepare(repo=repo, base=base, head=head)
        self.assertIn(raw_value.encode("ascii"), review.diff_file.read_bytes())
        self.assertEqual(
            (
                review.workspace_root
                / ".codex-review"
                / workspace.CHANGED_PATH_DIGESTS_NAME
            ).read_bytes(),
            b"",
        )
        self.assertEqual(
            (review.container_dir / workspace.PRIVATE_CHANGED_PATHS_NAME).read_bytes(),
            b"",
        )
        self.validate(review)

    def test_dynamic_value_matching_changed_path_digest_fails_closed(self) -> None:
        relative = "fixture.cfg"
        raw_value = hashlib.sha256(relative.encode("ascii")).hexdigest()
        fixture = assignment_text("password", raw_value)
        repo, base = self.new_repo({relative: fixture * 2})
        (repo / relative).write_text(fixture, encoding="utf-8")
        head = self.commit(repo)

        with self.assertRaisesRegex(
            ReviewError,
            "would expose a raw synthetic value",
        ) as caught:
            self.prepare(repo=repo, base=base, head=head)
        self.assertNotIn(raw_value, str(caught.exception))

    def test_retained_container_removes_helper_private_artifacts(self) -> None:
        fixture = reduction_fixture("generic-secret-assignment")
        secret = reduction_secret("generic-secret-assignment")
        repo, base = self.new_repo({"fixture.cfg": fixture * 2})
        (repo / "fixture.cfg").write_text(fixture, encoding="utf-8")
        head = self.commit(repo)
        review = self.prepare(repo=repo, base=base, head=head)
        private_paths = review.container_dir / workspace.PRIVATE_CHANGED_PATHS_NAME
        private_manifest = (
            review.container_dir / workspace.SYNTHETIC_PRIVATE_MANIFEST_NAME
        )
        self.assertTrue(private_paths.exists())
        self.assertIn(
            base64.b64encode(secret),
            private_manifest.read_bytes(),
        )

        self.assertIsNone(workspace.cleanup_workspace(review, keep_container=True))

        self.assertTrue(review.container_dir.exists())
        self.assertFalse(review.workspace_root.exists())
        self.assertFalse(private_paths.exists())
        self.assertFalse(private_manifest.exists())

    def test_retained_container_removes_private_paths_when_cleanup_fails(
        self,
    ) -> None:
        repo, base = self.new_repo({"README.md": "base\n"})
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        review = self.prepare(repo=repo, base=base, head=head)
        private_paths = review.container_dir / workspace.PRIVATE_CHANGED_PATHS_NAME
        private_manifest = (
            review.container_dir / workspace.SYNTHETIC_PRIVATE_MANIFEST_NAME
        )
        self.assertTrue(private_paths.exists())
        self.assertTrue(private_manifest.exists())

        with mock.patch.object(
            workspace.shutil,
            "rmtree",
            side_effect=PermissionError("permission denied"),
        ) as remove_tree:
            cleanup_error = workspace.cleanup_workspace(
                review,
                keep_container=True,
            )

        self.assertIn("permission denied", cleanup_error or "")
        remove_tree.assert_called_once_with("workspace", dir_fd=mock.ANY)
        self.assertTrue(review.container_dir.exists())
        self.assertTrue(review.workspace_root.exists())
        self.assertFalse(private_paths.exists())
        self.assertFalse(private_manifest.exists())

    def test_cleanup_validation_failure_removes_helper_private_artifacts(self) -> None:
        repo, base = self.new_repo({"README.md": "base\n"})
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        review = self.prepare(repo=repo, base=base, head=head)
        private_paths = review.container_dir / workspace.PRIVATE_CHANGED_PATHS_NAME
        private_manifest = (
            review.container_dir / workspace.SYNTHETIC_PRIVATE_MANIFEST_NAME
        )
        self.assertTrue(private_paths.exists())
        self.assertTrue(private_manifest.exists())

        with (
            mock.patch.object(
                workspace,
                "validate_workspace_layout",
                side_effect=ReviewError("layout invalid"),
            ),
            self.assertRaisesRegex(ReviewError, "layout invalid"),
        ):
            workspace.cleanup_workspace(review, keep_container=True)

        self.assertTrue(review.container_dir.exists())
        self.assertTrue(review.workspace_root.exists())
        self.assertFalse(private_paths.exists())
        self.assertFalse(private_manifest.exists())

        with (
            mock.patch.object(
                workspace,
                "validate_workspace_layout",
                side_effect=ReviewError("layout invalid"),
            ),
            mock.patch.object(
                workspace,
                "remove_private_review_artifacts",
                return_value="unlink denied",
            ),
            self.assertRaisesRegex(
                ReviewError,
                "layout invalid; private artifact cleanup failed: unlink denied",
            ),
        ):
            workspace.cleanup_workspace(review, keep_container=True)

    def test_jwt_base64url_suffix_extraction_does_not_count_as_reduction(self) -> None:
        shorter = reduction_secret("jwt").decode("ascii")
        longer = shorter + "-"
        repo, base = self.new_repo({"fixture.txt": (longer + "!\n") * 2})
        (repo / "fixture.txt").write_text(shorter + "!\n", encoding="utf-8")
        head = self.commit(repo)

        with self.assertRaisesRegex(
            ReviewError,
            "unregistered secret unembedded count increased",
        ):
            self.prepare(repo=repo, base=base, head=head)

    def test_jwe_shared_prefix_replacement_does_not_count_as_reduction(self) -> None:
        shared_prefix = "eyJ" + "A" * 12 + ".." + "C" * 12

        def jwe(fourth: str, fifth: str) -> str:
            return f"{shared_prefix}.{fourth * 12}.{fifth * 12}"

        repo, base = self.new_repo(
            {"fixture.txt": f"{jwe('D', 'E')}\n{jwe('F', 'G')}\n"}
        )
        (repo / "fixture.txt").write_text(
            f"{jwe('H', 'I')}\n",
            encoding="utf-8",
        )
        head = self.commit(repo)

        with self.assertRaisesRegex(ReviewError, "jwt"):
            self.prepare(repo=repo, base=base, head=head)

    def test_google_api_key_suffix_replacement_does_not_count_as_reduction(
        self,
    ) -> None:
        cases = (
            ("hyphen-to-word", "-", ("X", "Y", "Z")),
            ("underscore-to-hyphen", "_", ("-X", "-Y", "-Z")),
        )
        for label, terminal, suffixes in cases:
            with self.subTest(case=label):
                truncated = "AIza" + "A" * 34 + terminal
                repo, base = self.new_repo(
                    {
                        "fixture.txt": (
                            f"{truncated}{suffixes[0]}\n{truncated}{suffixes[1]}\n"
                        )
                    }
                )
                (repo / "fixture.txt").write_text(
                    f"{truncated}{suffixes[2]}\n",
                    encoding="utf-8",
                )
                head = self.commit(repo)

                with self.assertRaisesRegex(ReviewError, "google-api-key"):
                    self.prepare(repo=repo, base=base, head=head)

    def test_unsafe_long_provider_rhs_does_not_count_as_reduction(self) -> None:
        candidate = b"sk-" + b"proj-B1" + b"B" * 506

        def unsafe_assignment(marker: bytes) -> str:
            return (
                b"api_" + b"token = " + candidate + b" \\" + b"\n" + marker + b"\n"
            ).decode("ascii")

        repo, base = self.new_repo(
            {
                "fixture.txt": unsafe_assignment(b"continued-a")
                + unsafe_assignment(b"continued-b")
            }
        )
        (repo / "fixture.txt").write_text(
            unsafe_assignment(b"continued-c"),
            encoding="utf-8",
        )
        head = self.commit(repo)

        with self.assertRaisesRegex(ReviewError, "generic-secret-assignment"):
            self.prepare(repo=repo, base=base, head=head)

    def test_unsafe_short_provider_rhs_does_not_count_as_reduction(self) -> None:
        candidate = b"ghp_" + b"A" * 36

        def unsafe_assignment(marker: bytes) -> str:
            return (
                b"api_" + b"token = " + candidate + b" \\" + b"\n" + marker + b"\n"
            ).decode("ascii")

        repo, base = self.new_repo(
            {
                "fixture.txt": unsafe_assignment(b"continued-a")
                + unsafe_assignment(b"continued-b")
            }
        )
        (repo / "fixture.txt").write_text(
            unsafe_assignment(b"continued-c"),
            encoding="utf-8",
        )
        head = self.commit(repo)

        with self.assertRaisesRegex(ReviewError, "generic-secret-assignment"):
            self.prepare(repo=repo, base=base, head=head)

    def test_provider_rhs_beyond_proof_cap_does_not_count_as_reduction(self) -> None:
        proof_bytes = 256
        candidate = b"ghp_" + b"A" * 36
        assignment_prefix = b"api_token = ("
        candidate_start = proof_bytes + 16
        wrapper_count = candidate_start - len(assignment_prefix)
        fixture = (
            assignment_prefix
            + b"(" * wrapper_count
            + candidate
            + b")" * (wrapper_count + 1)
            + b"\n"
        ).decode("ascii")
        repo, base = self.new_repo({"fixture.txt": fixture * 2})
        (repo / "fixture.txt").write_text(fixture, encoding="utf-8")
        head = self.commit(repo)

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            self.assertRaisesRegex(ReviewError, "generic-secret-assignment"),
        ):
            self.prepare(repo=repo, base=base, head=head)

    def test_delayed_provider_in_open_rhs_does_not_count_as_reduction(self) -> None:
        proof_bytes = 256
        overlap = 32
        _candidate, unsafe, _safe, _ordinary = rhs_proof_boundary_payloads()
        fixture = unsafe.decode("ascii")
        repo, base = self.new_repo({"fixture.txt": fixture * 2})
        (repo / "fixture.txt").write_text(fixture, encoding="utf-8")
        head = self.commit(repo)

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 64),
            self.assertRaisesRegex(ReviewError, "generic-secret-assignment"),
        ):
            self.prepare(repo=repo, base=base, head=head)

    def test_remote_provider_after_closed_rhs_keeps_reduction_semantics(
        self,
    ) -> None:
        proof_bytes = 256
        overlap = 32
        _candidate, _unsafe, safe, _ordinary = rhs_proof_boundary_payloads()
        fixture = safe.decode("ascii")
        repo, base = self.new_repo(
            {
                "fixture-a.txt": fixture,
                "fixture-b.txt": fixture,
            }
        )
        (repo / "fixture-b.txt").unlink()
        head = self.commit(repo)

        with (
            mock.patch.object(
                workspace,
                "MAX_SECRET_PREFIX_PROOF_BYTES",
                proof_bytes,
            ),
            mock.patch.object(workspace, "STREAM_SCAN_OVERLAP", overlap),
            mock.patch.object(workspace, "STREAM_SCAN_CHUNK_BYTES", 64),
        ):
            review = self.prepare(repo=repo, base=base, head=head)
            evidence = self.validate(review)

        reductions = evidence["synthetic_tokens"]["secret_reductions"]
        self.assertEqual(len(reductions), 1)
        self.assertEqual(reductions[0]["rules"], ["github-token"])
        self.assertEqual(
            (
                reductions[0]["base_count"],
                reductions[0]["head_count"],
            ),
            (2, 1),
        )
        self.assertEqual(
            (
                reductions[0]["base_unembedded_count"],
                reductions[0]["head_unembedded_count"],
            ),
            (2, 1),
        )

    def test_incomplete_quoted_short_provider_does_not_count_as_reduction(
        self,
    ) -> None:
        candidate = b"ghp_" + b"A" * 36

        def incomplete_assignment(marker: bytes) -> str:
            return (
                b"api_" + b'token = "' + candidate + b"\\" + b"\n" + marker + b'"\n'
            ).decode("ascii")

        repo, base = self.new_repo(
            {
                "fixture.txt": incomplete_assignment(b"continued-a")
                + incomplete_assignment(b"continued-b")
            }
        )
        (repo / "fixture.txt").write_text(
            incomplete_assignment(b"continued-c"),
            encoding="utf-8",
        )
        head = self.commit(repo)

        with self.assertRaisesRegex(ReviewError, "generic-secret-assignment"):
            self.prepare(repo=repo, base=base, head=head)

    def test_incomplete_rhs_wrapper_does_not_count_as_reduction(self) -> None:
        candidate = b"ghp_" + b"A" * 36
        cases = (
            ("unclosed-unquoted", b"api_token = (" + candidate + b"\n"),
            ("mismatched-unquoted", b"api_token = ([" + candidate + b")\n"),
            ("unclosed-quoted", b'api_token = ("' + candidate + b'"\n'),
            (
                "external-function-mismatch",
                b'configure(api_token = "' + candidate + b'"]\n',
            ),
            (
                "external-json-mismatch",
                b'[{"api_token": "' + candidate + b'")]\n',
            ),
            (
                "external-function-missing",
                b'configure(api_token = "' + candidate + b'"\n',
            ),
            (
                "external-json-missing",
                b'[{"api_token": "' + candidate + b'"}\n',
            ),
            (
                "external-function-missing-after-sibling",
                b'configure(api_token = "' + candidate + b'", state = "expired"\n',
            ),
            (
                "external-json-missing-after-sibling",
                b'[{"api_token": "' + candidate + b'", "state": "expired"}\n',
            ),
        )
        for label, raw_fixture in cases:
            with self.subTest(case=label):
                fixture = raw_fixture.decode("ascii")
                repo, base = self.new_repo({"fixture.txt": fixture * 2})
                (repo / "fixture.txt").write_text(fixture, encoding="utf-8")
                head = self.commit(repo)

                with self.assertRaisesRegex(
                    ReviewError,
                    "generic-secret-assignment",
                ):
                    self.prepare(repo=repo, base=base, head=head)

    def test_extended_short_provider_value_does_not_count_as_prefix_reduction(
        self,
    ) -> None:
        candidate = b"ghp_" + b"A" * 36

        def assignment(suffix: bytes) -> str:
            return (b"api_" + b"token = " + candidate + suffix + b"\n").decode("ascii")

        repo, base = self.new_repo(
            {"fixture.txt": assignment(b"+alpha") + assignment(b"+bravo")}
        )
        (repo / "fixture.txt").write_text(
            assignment(b"+charlie"),
            encoding="utf-8",
        )
        head = self.commit(repo)

        with self.assertRaisesRegex(ReviewError, "generic-secret-assignment"):
            self.prepare(repo=repo, base=base, head=head)

    def test_extended_short_provider_value_can_strictly_reduce_when_exact(
        self,
    ) -> None:
        candidate = b"ghp_" + b"A" * 36
        fixture = (b"api_" + b"token = " + candidate + b"+alpha\n").decode("ascii")
        repo, base = self.new_repo({"fixture.txt": fixture * 2})
        (repo / "fixture.txt").write_text(fixture, encoding="utf-8")
        head = self.commit(repo)

        review = self.prepare(repo=repo, base=base, head=head)
        evidence = self.validate(review)
        reductions = evidence["synthetic_tokens"]["secret_reductions"]
        self.assertEqual(len(reductions), 2)
        self.assertEqual(
            {tuple(entry["rules"]) for entry in reductions},
            {("generic-secret-assignment",), ("github-token",)},
        )
        self.assertTrue(
            all(
                (entry["base_count"], entry["head_count"]) == (2, 1)
                for entry in reductions
            )
        )

    def test_fixed_length_provider_suffix_does_not_count_as_prefix_reduction(
        self,
    ) -> None:
        cases = (
            ("aws-access-key", b"AKIA" + b"A" * 16),
            ("npm-token", b"npm_" + b"A" * 36),
        )
        for rule, candidate in cases:
            with self.subTest(rule=rule):

                def assignment(suffix: bytes) -> str:
                    return (b"api_" + b"token = " + candidate + suffix + b"\n").decode(
                        "ascii"
                    )

                repo, base = self.new_repo(
                    {"fixture.txt": assignment(b"_alpha") + assignment(b"_bravo")}
                )
                (repo / "fixture.txt").write_text(
                    assignment(b"_charlie"),
                    encoding="utf-8",
                )
                head = self.commit(repo)

                with self.assertRaisesRegex(
                    ReviewError,
                    "generic-secret-assignment",
                ):
                    self.prepare(repo=repo, base=base, head=head)

    def test_fixed_length_provider_suffix_can_strictly_reduce_when_exact(
        self,
    ) -> None:
        cases = (
            ("aws-access-key", b"AKIA" + b"A" * 16),
            ("npm-token", b"npm_" + b"A" * 36),
        )
        for rule, candidate in cases:
            with self.subTest(rule=rule):
                fixture = (b"api_" + b"token = " + candidate + b"_suffix\n").decode(
                    "ascii"
                )
                repo, base = self.new_repo({"fixture.txt": fixture * 2})
                (repo / "fixture.txt").write_text(fixture, encoding="utf-8")
                head = self.commit(repo)

                review = self.prepare(repo=repo, base=base, head=head)
                evidence = self.validate(review)
                reductions = evidence["synthetic_tokens"]["secret_reductions"]
                self.assertEqual(len(reductions), 2)
                self.assertEqual(
                    {tuple(entry["rules"]) for entry in reductions},
                    {("generic-secret-assignment",), (rule,)},
                )
                self.assertTrue(
                    all(
                        (entry["base_count"], entry["head_count"]) == (2, 1)
                        for entry in reductions
                    )
                )

    def test_prepared_range_rejects_non_decreasing_secret_transitions(self) -> None:
        cases = (
            ("equal", "generic-secret-assignment"),
            ("move", "jwt"),
            ("copy", "github-token"),
            ("add", "generic-secret-assignment"),
            ("replace", "github-token"),
        )
        for transition, rule in cases:
            with self.subTest(transition=transition, rule=rule):
                fixture_a = reduction_fixture(rule, b"A")
                fixture_b = reduction_fixture(rule, b"B")
                base_files = (
                    {"README.md": "base\n"}
                    if transition == "add"
                    else {"fixture.cfg": fixture_a}
                )
                repo, base = self.new_repo(base_files)
                if transition == "equal":
                    (repo / "README.md").write_text("head\n", encoding="utf-8")
                elif transition == "move":
                    (repo / "moved.cfg").write_text(fixture_a, encoding="utf-8")
                    (repo / "fixture.cfg").unlink()
                elif transition == "copy":
                    (repo / "copied.cfg").write_text(fixture_a, encoding="utf-8")
                elif transition == "add":
                    (repo / "fixture.cfg").write_text(fixture_a, encoding="utf-8")
                else:
                    (repo / "fixture.cfg").write_text(fixture_b, encoding="utf-8")
                head = self.commit(repo)

                with self.assertRaisesRegex(ReviewError, rule):
                    self.prepare(repo=repo, base=base, head=head)

    def test_prepared_range_rejects_net_reduction_with_new_occurrence_provenance(
        self,
    ) -> None:
        fixture = reduction_fixture("generic-secret-assignment")
        cases = ("path", "offset", "mode")
        for transition in cases:
            with self.subTest(transition=transition):
                if transition == "path":
                    repo, base = self.new_repo(
                        {"first.cfg": fixture, "second.cfg": fixture}
                    )
                    (repo / "first.cfg").unlink()
                    (repo / "second.cfg").unlink()
                    (repo / "relocated.cfg").write_text(fixture, encoding="utf-8")
                elif transition == "offset":
                    repo, base = self.new_repo(
                        {"fixture.cfg": fixture + "# padding\n" + fixture}
                    )
                    (repo / "fixture.cfg").write_text(
                        "# shifted\n" + fixture,
                        encoding="utf-8",
                    )
                else:
                    mode_value = reduction_secret("github-token").decode("ascii")
                    repo, base = self.new_repo(
                        {"fixture.cfg": mode_value, "extra.cfg": mode_value}
                    )
                    (repo / "extra.cfg").unlink()
                    (repo / "fixture.cfg").unlink()
                    (repo / "fixture.cfg").symlink_to(mode_value)
                head = self.commit(repo)

                with self.assertRaisesRegex(
                    ReviewError,
                    "head-side occurrence",
                ):
                    self.prepare(repo=repo, base=base, head=head)

    def test_prepared_range_rejects_new_unembedded_occurrence_at_stable_offset(
        self,
    ) -> None:
        short = reduction_secret("generic-secret-assignment").decode("ascii")
        prefix = "Prefix"
        longer = prefix + short + "Suffix"
        assignment_prefix = "access_token = "
        base_first = assignment_prefix + '"' + longer + '"\n'
        head_first = assignment_prefix + " " * len(prefix) + '"' + short + '"\n'
        self.assertEqual(base_first.index(short), head_first.index(short))
        repo, base = self.new_repo(
            {"fixture.cfg": base_first + assignment_text("refresh_token", short)}
        )
        (repo / "fixture.cfg").write_text(head_first, encoding="utf-8")
        head = self.commit(repo)

        with self.assertRaisesRegex(
            ReviewError,
            "unembedded head-side occurrence",
        ):
            self.prepare(repo=repo, base=base, head=head)

    def test_dynamic_reduction_provenance_covers_binary_and_symlink_modes(
        self,
    ) -> None:
        candidate = reduction_secret("github-token")
        for surface in ("binary", "symlink", "chmod"):
            with self.subTest(surface=surface):
                if surface == "binary":
                    fixture = b"\x00" + candidate + b"\x00"
                    repo, _initial = self.new_repo({"README.md": "base\n"})
                    (repo / "fixture.bin").write_bytes(fixture * 2)
                    base = self.commit(repo, "Binary base")
                    (repo / "fixture.bin").write_bytes(fixture)
                elif surface == "symlink":
                    repo, base = self.new_repo({"README.md": "base\n"})
                    target = candidate.decode("ascii")
                    (repo / "first.link").symlink_to(target)
                    (repo / "second.link").symlink_to(target)
                    base = self.commit(repo)
                    (repo / "second.link").unlink()
                else:
                    fixture = reduction_fixture("generic-secret-assignment")
                    repo, base = self.new_repo({"fixture.cfg": fixture * 2})
                    (repo / "fixture.cfg").write_text(fixture, encoding="utf-8")
                    (repo / "fixture.cfg").chmod(0o755)
                head = self.commit(repo)

                review = self.prepare(repo=repo, base=base, head=head)
                evidence = self.validate(review)
                reductions = evidence["synthetic_tokens"]["secret_reductions"]
                self.assertEqual(len(reductions), 1)
                self.assertEqual(
                    (reductions[0]["base_count"], reductions[0]["head_count"]),
                    (2, 1),
                )

    def test_preparation_rejects_two_to_one_shared_provider_prefix_replacement(
        self,
    ) -> None:
        shared_prefix = b"glpat-" + b"D" * 512
        base_fixture = b"\n".join(
            (shared_prefix + b"-suffix-a", shared_prefix + b"-suffix-b")
        )
        head_fixture = shared_prefix + b"-suffix-c\n"
        repo, base = self.new_repo({"fixture.txt": base_fixture.decode("ascii") + "\n"})
        (repo / "fixture.txt").write_bytes(head_fixture)
        head = self.commit(repo)

        with self.assertRaisesRegex(ReviewError, "gitlab-token"):
            self.prepare(repo=repo, base=base, head=head)

    def test_pem_reduction_uses_the_complete_block_as_candidate_identity(self) -> None:
        base_fixture = reduction_fixture("private-key", b"A") + reduction_fixture(
            "private-key", b"B"
        )
        head_fixture = reduction_fixture("private-key", b"C")
        repo, base = self.new_repo({"fixture.pem": base_fixture})
        (repo / "fixture.pem").write_text(head_fixture, encoding="utf-8")
        head = self.commit(repo)

        with self.assertRaisesRegex(ReviewError, "private-key"):
            review = self.prepare(repo=repo, base=base, head=head)
            self.validate(review)

    def test_dynamic_path_digest_cannot_expose_an_authoring_value(self) -> None:
        relative = "fixture.cfg"
        raw_value = hashlib.sha256(relative.encode("ascii")).hexdigest()[:24]
        payload = catalog_payload()
        payload["authoring_pool"]["tokens"][0]["value"] = raw_value
        catalog = synthetic_tokens.parse_catalog_bytes(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        repo, base = self.new_repo({"README.md": "base\n"})
        (repo / relative).write_text(
            assignment_text("access_token", raw_value),
            encoding="utf-8",
        )
        head = self.commit(repo)
        with self.assertRaisesRegex(
            ReviewError,
            "would expose a raw synthetic value",
        ) as caught:
            self.prepare(repo=repo, base=base, head=head, catalog=catalog)
        self.assertNotIn(raw_value, str(caught.exception))

    def test_dynamic_path_digest_cannot_expose_a_legacy_value(self) -> None:
        relative = "fixture.cfg"
        raw_value = hashlib.sha256(relative.encode("ascii")).hexdigest()[:24]
        catalog = legacy_catalog(values=(raw_value,))
        repo, base = self.new_repo(
            {relative: assignment_text("access_token", raw_value)}
        )
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        review = self.prepare(
            repo=repo,
            base=base,
            head=head,
            catalog=catalog,
            exemptions=("historical-fixtures",),
        )
        with self.assertRaisesRegex(
            ReviewError,
            "would expose a raw synthetic value",
        ) as caught:
            self.validate(review, catalog=catalog)
        self.assertNotIn(raw_value, str(caught.exception))

    def test_escaping_legacy_symlink_target_is_redacted_during_materialization(
        self,
    ) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        for label, sensitive_target in (
            ("raw", LEGACY_A),
            ("storage", legacy_value_base64(LEGACY_A)),
        ):
            with self.subTest(target=label):
                repo, base = self.new_repo({"README.md": "base\n"})
                (repo / "artifact").symlink_to("../" + sensitive_target)
                head = self.commit(repo)
                with self.assertRaisesRegex(
                    ReviewError,
                    "<redacted symlink target>",
                ) as caught:
                    self.prepare(repo=repo, base=base, head=head, catalog=catalog)
                message = str(caught.exception)
                self.assertNotIn(LEGACY_A, message)
                self.assertNotIn(legacy_value_base64(LEGACY_A), message)

    def test_tampered_escaping_legacy_symlink_target_is_redacted_during_validation(
        self,
    ) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        for label, sensitive_target in (
            ("raw", LEGACY_A),
            ("storage", legacy_value_base64(LEGACY_A)),
        ):
            with self.subTest(target=label):
                repo, base = self.new_repo({"target.txt": "safe\n"})
                (repo / "artifact").symlink_to("target.txt")
                head = self.commit(repo)
                review = self.prepare(
                    repo=repo,
                    base=base,
                    head=head,
                    catalog=catalog,
                )
                frozen_link = review.workspace_root / "artifact"
                frozen_link.unlink()
                frozen_link.symlink_to("../../../../" + sensitive_target)
                with self.assertRaisesRegex(
                    ReviewError,
                    "<redacted symlink target>",
                ) as caught:
                    self.validate(review, catalog=catalog)
                message = str(caught.exception)
                self.assertNotIn(LEGACY_A, message)
                self.assertNotIn(legacy_value_base64(LEGACY_A), message)

    def test_evidence_cannot_expose_legacy_storage_encoding(self) -> None:
        raw_value = "jgajgajgajgajgajga"
        catalog = legacy_catalog(values=(raw_value,))
        accepted = synthetic_tokens.accepted_legacy_values(
            catalog,
            catalog.legacy_exemptions,
        )
        with self.assertRaisesRegex(
            ReviewError,
            "would expose a raw synthetic value",
        ) as caught:
            workspace._reject_raw_values_in_evidence(
                {"dynamic": legacy_value_base64(raw_value)},
                accepted_values=accepted,
                label="test evidence",
            )
        self.assertNotIn(raw_value, str(caught.exception))
        self.assertNotIn(legacy_value_base64(raw_value), str(caught.exception))

    def test_evidence_cannot_expose_a_numeric_synthetic_value(self) -> None:
        integer_raw = "12345678" + "90123456"
        float_raw = "1.23456789" + "0123456"
        cases = (
            ("integer-key", integer_raw, {int(integer_raw): "metadata"}),
            ("integer-value", integer_raw, {"inode": int(integer_raw)}),
            ("float-value", float_raw, {"ratio": float(float_raw)}),
        )
        for label, raw_value, evidence in cases:
            with self.subTest(case=label):
                accepted = (
                    accepted_legacy_value(
                        raw_value,
                        rule="generic-secret-assignment",
                    ),
                )
                with self.assertRaisesRegex(
                    ReviewError,
                    "would expose a raw synthetic value",
                ) as caught:
                    workspace._reject_raw_values_in_evidence(
                        evidence,
                        accepted_values=accepted,
                        label="test evidence",
                    )
                self.assertNotIn(raw_value, str(caught.exception))

                destination = self.root / f"numeric-evidence-{label}.json"
                with self.assertRaisesRegex(
                    ReviewError,
                    "would expose a raw synthetic value",
                ):
                    workspace._write_bounded_json(
                        destination,
                        evidence,
                        label="test evidence",
                        accepted_values=accepted,
                    )
                self.assertFalse(destination.exists())

    def test_non_finite_evidence_numbers_fail_closed(self) -> None:
        for label, value in (
            ("nan", float("nan")),
            ("negative-infinity", float("-inf")),
            ("positive-infinity", float("inf")),
        ):
            with self.subTest(case=label):
                destination = self.root / f"non-finite-{label}.json"
                with self.assertRaisesRegex(
                    ReviewError,
                    "not safely JSON serializable",
                ):
                    workspace._write_bounded_json(
                        destination,
                        {"value": value},
                        label="test evidence",
                    )
                self.assertFalse(destination.exists())

        destination = self.root / "ordinary-scalars.json"
        workspace._write_bounded_json(
            destination,
            {"enabled": True, "missing": None},
            label="test evidence",
        )
        self.assertEqual(
            json.loads(destination.read_text(encoding="utf-8")),
            {"enabled": True, "missing": None},
        )

    def test_review_range_cannot_expose_an_unused_authoring_value(self) -> None:
        repo, base = self.new_repo({"README.md": "base\n"})
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        raw_value = f"{base}..{head}"
        payload = catalog_payload()
        payload["authoring_pool"]["tokens"][0]["value"] = raw_value
        catalog = synthetic_tokens.parse_catalog_bytes(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        review = self.prepare(repo=repo, base=base, head=head, catalog=catalog)
        with self.assertRaisesRegex(
            ReviewError,
            "would expose a raw synthetic value",
        ) as caught:
            self.validate(review, catalog=catalog)
        self.assertNotIn(raw_value, str(caught.exception))

    def test_review_range_cannot_expose_an_unselected_legacy_value(self) -> None:
        repo, base = self.new_repo({"README.md": "base\n"})
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        raw_value = f"{base}..{head}"
        catalog = legacy_catalog(values=(raw_value,))
        review = self.prepare(repo=repo, base=base, head=head, catalog=catalog)
        with self.assertRaisesRegex(
            ReviewError,
            "would expose a raw synthetic value",
        ) as caught:
            self.validate(review, catalog=catalog)
        self.assertNotIn(raw_value, str(caught.exception))

    def test_pool_value_in_credential_path_remains_blocked(self) -> None:
        repo, base = self.new_repo({"README.md": "base\n"})
        (repo / "auth.json").write_text(
            json.dumps({"access_token": AUTHORING_VALUES[0]}),
            encoding="utf-8",
        )
        head = self.commit(repo)
        review = self.prepare(repo=repo, base=base, head=head)
        with self.assertRaisesRegex(ReviewError, "credential-path"):
            self.validate(review)

    def test_non_pool_synthetic_looking_value_in_unchanged_head_is_blocked(
        self,
    ) -> None:
        unknown = "codex_public_synth_v1_access_unknown"
        repo, base = self.new_repo(
            {"fixture.cfg": f'access_token = "{unknown}"\n', "README.md": "base\n"}
        )
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        with self.assertRaisesRegex(ReviewError, "generic-secret-assignment") as raised:
            self.prepare(repo=repo, base=base, head=head)
        self.assertNotIn(unknown, str(raised.exception))

    def test_multi_value_legacy_unchanged_and_deleted_counts_pass(self) -> None:
        catalog = legacy_catalog()
        cases = {
            "unchanged": (
                f'access_token = "{LEGACY_A}"\nrefresh_token = "{LEGACY_B}"\n',
                f'access_token = "{LEGACY_A}"\nrefresh_token = "{LEGACY_B}"\n',
            ),
            "deleted": (
                f'access_token = "{LEGACY_A}"\nrefresh_token = "{LEGACY_B}"\n',
                f'access_token = "{LEGACY_A}"\n',
            ),
        }
        for label, (base_fixture, head_fixture) in cases.items():
            with self.subTest(case=label):
                repo, base = self.new_repo(
                    {"fixture.cfg": base_fixture, "README.md": "base\n"}
                )
                (repo / "fixture.cfg").write_text(head_fixture, encoding="utf-8")
                (repo / "README.md").write_text("head\n", encoding="utf-8")
                head = self.commit(repo)
                review = self.prepare(
                    repo=repo,
                    base=base,
                    head=head,
                    catalog=catalog,
                    exemptions=("historical-fixtures",),
                )
                evidence = self.validate(review, catalog=catalog)
                legacy_counts = evidence["synthetic_tokens"]["legacy_counts"]
                self.assertEqual(len(legacy_counts), 2)
                self.assertNotIn(LEGACY_A, json.dumps(evidence, sort_keys=True))
                self.assertNotIn(LEGACY_B, json.dumps(evidence, sort_keys=True))

    def test_printable_legacy_value_passes_only_when_selected(self) -> None:
        catalog = legacy_catalog(values=(LEGACY_PRINTABLE,))
        repo, base = self.new_repo(
            {"fixture.cfg": assignment_text("access_token", LEGACY_PRINTABLE)}
        )
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)

        review = self.prepare(
            repo=repo,
            base=base,
            head=head,
            catalog=catalog,
            exemptions=("historical-fixtures",),
        )
        evidence = self.validate(review, catalog=catalog)
        counts = evidence["synthetic_tokens"]["legacy_counts"]
        self.assertEqual(
            (counts[0]["base_count"], counts[0]["head_count"]),
            (1, 1),
        )
        serialized = json.dumps(evidence, sort_keys=True)
        self.assertNotIn(LEGACY_PRINTABLE, serialized)
        self.assertNotIn(legacy_value_base64(LEGACY_PRINTABLE), serialized)

        with self.assertRaisesRegex(ReviewError, "generic-secret-assignment"):
            self.prepare(
                repo=repo,
                base=base,
                head=head,
                catalog=catalog,
            )

    def test_unselected_legacy_reduction_requires_explicit_exemption(self) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        fixture = assignment_text("access_token", LEGACY_A)
        repo, base = self.new_repo({"fixture.cfg": fixture * 2})
        (repo / "fixture.cfg").write_text(fixture, encoding="utf-8")
        head = self.commit(repo)

        with mock.patch.object(
            workspace,
            "_secret_reduction_descriptor",
            wraps=workspace._secret_reduction_descriptor,
        ) as descriptor:
            with self.assertRaisesRegex(
                ReviewError,
                "explicitly selected synthetic secret exemption",
            ) as raised:
                self.prepare(
                    repo=repo,
                    base=base,
                    head=head,
                    catalog=catalog,
                )
        descriptor.assert_not_called()
        self.assertNotIn(LEGACY_A, str(raised.exception))

        review = self.prepare(
            repo=repo,
            base=base,
            head=head,
            catalog=catalog,
            exemptions=("historical-fixtures",),
        )
        evidence = self.validate(review, catalog=catalog)
        counts = evidence["synthetic_tokens"]["legacy_counts"]
        self.assertEqual(len(counts), 1)
        self.assertEqual(
            (counts[0]["base_count"], counts[0]["head_count"]),
            (2, 1),
        )
        self.assertEqual(evidence["synthetic_tokens"]["secret_reductions"], [])

    def test_unselected_legacy_substring_reduction_requires_explicit_exemption(
        self,
    ) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        embedded_value = "Prefix" + LEGACY_A + "Suffix"
        fixture = assignment_text("access_token", embedded_value)
        repo, base = self.new_repo({"fixture.cfg": fixture * 2})
        (repo / "fixture.cfg").write_text(fixture, encoding="utf-8")
        head = self.commit(repo)

        with mock.patch.object(
            workspace,
            "_secret_reduction_descriptor",
            wraps=workspace._secret_reduction_descriptor,
        ) as descriptor:
            with self.assertRaisesRegex(
                ReviewError,
                "explicitly selected synthetic secret exemption",
            ) as raised:
                self.prepare(
                    repo=repo,
                    base=base,
                    head=head,
                    catalog=catalog,
                )
        descriptor.assert_not_called()
        self.assertNotIn(LEGACY_A, str(raised.exception))
        self.assertNotIn(embedded_value, str(raised.exception))

        review = self.prepare(
            repo=repo,
            base=base,
            head=head,
            catalog=catalog,
            exemptions=("historical-fixtures",),
        )
        evidence = self.validate(review, catalog=catalog)
        counts = evidence["synthetic_tokens"]["legacy_counts"]
        reductions = evidence["synthetic_tokens"]["secret_reductions"]
        self.assertEqual(len(counts), 1)
        self.assertEqual(
            (counts[0]["base_count"], counts[0]["head_count"]),
            (2, 1),
        )
        self.assertEqual(len(reductions), 1)
        self.assertEqual(
            (reductions[0]["base_count"], reductions[0]["head_count"]),
            (2, 1),
        )

    def test_legacy_counts_accept_authoring_values_but_not_unknown_secrets(
        self,
    ) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        fixture = assignment_text(
            "access_token", AUTHORING_VALUES[0]
        ) + assignment_text("refresh_token", LEGACY_A)
        repo, base = self.new_repo({"fixture.cfg": fixture})
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        review = self.prepare(
            repo=repo,
            base=base,
            head=head,
            catalog=catalog,
            exemptions=("historical-fixtures",),
        )
        evidence = self.validate(review, catalog=catalog)
        counts = evidence["synthetic_tokens"]["legacy_counts"]
        self.assertEqual(len(counts), 1)
        self.assertEqual((counts[0]["base_count"], counts[0]["head_count"]), (1, 1))

        unknown_repo, unknown_base = self.new_repo(
            {
                "fixture.cfg": fixture
                + assignment_text("id_token", "UnknownSecretValueA9Z8Y7")
            }
        )
        (unknown_repo / "README.md").write_text("head\n", encoding="utf-8")
        unknown_head = self.commit(unknown_repo)
        with self.assertRaisesRegex(ReviewError, "generic-secret-assignment"):
            self.prepare(
                repo=unknown_repo,
                base=unknown_base,
                head=unknown_head,
                catalog=catalog,
                exemptions=("historical-fixtures",),
            )

    def test_github_legacy_assignment_uses_the_provider_specific_exemption(
        self,
    ) -> None:
        catalog = legacy_catalog(values=(GITHUB_LEGACY,), rule="github-token")
        repo, base = self.new_repo(
            {"fixture.cfg": assignment_text("access_token", GITHUB_LEGACY)}
        )
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        review = self.prepare(
            repo=repo,
            base=base,
            head=head,
            catalog=catalog,
            exemptions=("historical-fixtures",),
        )
        evidence = self.validate(review, catalog=catalog)
        counts = evidence["synthetic_tokens"]["legacy_counts"]
        self.assertEqual(len(counts), 1)
        self.assertEqual(counts[0]["rule"], "github-token")
        self.assertEqual(counts[0]["base_count"], 1)
        self.assertEqual(counts[0]["head_count"], 1)
        self.assertNotIn(GITHUB_LEGACY, json.dumps(evidence, sort_keys=True))

    def test_multi_value_legacy_move_and_rename_pass(self) -> None:
        catalog = legacy_catalog()
        repo, base = self.new_repo(
            {
                "old/fixture.cfg": (
                    f'access_token = "{LEGACY_A}"\nrefresh_token = "{LEGACY_B}"\n'
                )
            }
        )
        (repo / "new").mkdir()
        shutil.move(repo / "old/fixture.cfg", repo / "new/renamed.cfg")
        (repo / "old").rmdir()
        head = self.commit(repo)
        review = self.prepare(
            repo=repo,
            base=base,
            head=head,
            catalog=catalog,
            exemptions=("historical-fixtures",),
        )
        evidence = self.validate(review, catalog=catalog)
        self.assertTrue(
            all(
                entry["base_count"] == entry["head_count"] == 1
                for entry in evidence["synthetic_tokens"]["legacy_counts"]
            )
        )

    def test_selected_legacy_value_cannot_move_from_content_into_a_path(self) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        repo, base = self.new_repo(
            {"fixture.cfg": assignment_text("access_token", LEGACY_A)}
        )
        (repo / "fixture.cfg").unlink()
        (repo / f"moved-{LEGACY_A}.txt").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)

        with self.assertRaisesRegex(
            ReviewError,
            "not allowed in repository paths",
        ) as caught:
            self.prepare(
                repo=repo,
                base=base,
                head=head,
                catalog=catalog,
                exemptions=("historical-fixtures",),
            )
        self.assertNotIn(LEGACY_A, str(caught.exception))

    def test_selected_legacy_value_cannot_be_copied_from_content_into_a_path(
        self,
    ) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        repo, base = self.new_repo(
            {"fixture.cfg": assignment_text("access_token", LEGACY_A)}
        )
        (repo / f"copied-{LEGACY_A}.txt").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)

        with self.assertRaisesRegex(
            ReviewError,
            "not allowed in repository paths",
        ) as caught:
            self.prepare(
                repo=repo,
                base=base,
                head=head,
                catalog=catalog,
                exemptions=("historical-fixtures",),
            )
        self.assertNotIn(LEGACY_A, str(caught.exception))

    def test_legacy_storage_encoding_cannot_appear_in_a_path(self) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        storage = legacy_value_base64(LEGACY_A)
        repo, base = self.new_repo({"README.md": "base\n"})
        (repo / f"fixture-{storage}.txt").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)

        with self.assertRaisesRegex(
            ReviewError,
            "not allowed in repository paths",
        ) as caught:
            self.prepare(repo=repo, base=base, head=head, catalog=catalog)
        message = str(caught.exception)
        self.assertNotIn(storage, message)
        self.assertNotIn(LEGACY_A, message)

    def test_unselected_legacy_value_cannot_appear_in_a_path(self) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        repo, base = self.new_repo({"README.md": "base\n"})
        (repo / f"fixture-{LEGACY_A}.txt").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)

        with self.assertRaisesRegex(
            ReviewError,
            "not allowed in repository paths",
        ) as caught:
            self.prepare(repo=repo, base=base, head=head, catalog=catalog)
        self.assertNotIn(LEGACY_A, str(caught.exception))

    def test_deleted_or_renamed_base_legacy_path_remains_blocked(self) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        storage = legacy_value_base64(LEGACY_A)
        cases = {
            "deleted-raw": (LEGACY_A, None),
            "renamed-storage": (storage, "safe-name.txt"),
        }
        for label, (path_value, destination) in cases.items():
            with self.subTest(case=label):
                source = f"fixture-{path_value}.txt"
                repo, base = self.new_repo({source: "base\n"})
                if destination is None:
                    (repo / source).unlink()
                else:
                    (repo / source).rename(repo / destination)
                head = self.commit(repo)

                with self.assertRaisesRegex(
                    ReviewError,
                    "not allowed in repository paths",
                ) as caught:
                    self.prepare(repo=repo, base=base, head=head, catalog=catalog)
                self.assertNotIn(path_value, str(caught.exception))

    def test_legacy_add_and_copy_fail_count_gate(self) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        cases = {
            "add": ({"README.md": "base\n"}, {"fixture.cfg": LEGACY_A}),
            "copy": (
                {"fixture.cfg": f'access_token = "{LEGACY_A}"\n'},
                {
                    "fixture.cfg": f'access_token = "{LEGACY_A}"\n',
                    "copy.cfg": f'access_token = "{LEGACY_A}"\n',
                },
            ),
        }
        for label, (base_files, head_files) in cases.items():
            with self.subTest(case=label):
                repo, base = self.new_repo(base_files)
                for relative, value in head_files.items():
                    path = repo / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if label == "add":
                        value = f'access_token = "{value}"\n'
                    path.write_text(value, encoding="utf-8")
                head = self.commit(repo)
                with self.assertRaisesRegex(ReviewError, "count increased"):
                    self.prepare(
                        repo=repo,
                        base=base,
                        head=head,
                        catalog=catalog,
                        exemptions=("historical-fixtures",),
                    )

    def test_legacy_plain_text_and_binary_copies_fail_global_raw_count_gate(
        self,
    ) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        for label, copied_bytes in (
            ("plain", b"note: " + LEGACY_A.encode("ascii") + b"\n"),
            ("binary", b"\x00prefix\x00" + LEGACY_A.encode("ascii") + b"\x00suffix"),
        ):
            with self.subTest(case=label):
                repo, base = self.new_repo(
                    {"fixture.cfg": assignment_text("access_token", LEGACY_A)}
                )
                (repo / f"{label}.bin").write_bytes(copied_bytes)
                head = self.commit(repo)
                with self.assertRaisesRegex(ReviewError, "count increased"):
                    self.prepare(
                        repo=repo,
                        base=base,
                        head=head,
                        catalog=catalog,
                        exemptions=("historical-fixtures",),
                    )

    def test_legacy_value_can_move_from_assignment_to_plain_text(self) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        repo, base = self.new_repo(
            {"fixture.cfg": assignment_text("access_token", LEGACY_A)}
        )
        (repo / "fixture.cfg").unlink()
        (repo / "notes.txt").write_text(
            f"historical fixture: {LEGACY_A}\n",
            encoding="utf-8",
        )
        head = self.commit(repo)
        review = self.prepare(
            repo=repo,
            base=base,
            head=head,
            catalog=catalog,
            exemptions=("historical-fixtures",),
        )
        evidence = self.validate(review, catalog=catalog)
        counts = evidence["synthetic_tokens"]["legacy_counts"]
        self.assertEqual((counts[0]["base_count"], counts[0]["head_count"]), (1, 1))
        self.assertEqual(
            (
                counts[0]["base_unembedded_count"],
                counts[0]["head_unembedded_count"],
            ),
            (1, 1),
        )

    def test_frozen_head_plain_text_tampering_fails_raw_count_revalidation(
        self,
    ) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        repo, base = self.new_repo(
            {"fixture.cfg": assignment_text("access_token", LEGACY_A)}
        )
        (repo / "fixture.cfg").unlink()
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        review = self.prepare(
            repo=repo,
            base=base,
            head=head,
            catalog=catalog,
            exemptions=("historical-fixtures",),
        )
        (review.workspace_root / "tampered.txt").write_text(
            f"plain text {LEGACY_A}\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            ReviewError,
            "count changed after preparation",
        ):
            self.validate(review, catalog=catalog)

    def test_snapshot_path_rename_to_legacy_value_fails_revalidation(self) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        repo, base = self.new_repo(
            {
                "fixture.cfg": assignment_text("access_token", LEGACY_A),
                "safe.txt": "safe\n",
            }
        )
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        review = self.prepare(
            repo=repo,
            base=base,
            head=head,
            catalog=catalog,
            exemptions=("historical-fixtures",),
        )
        (review.workspace_root / "safe.txt").rename(
            review.workspace_root / f"moved-{LEGACY_A}.txt"
        )

        with self.assertRaisesRegex(
            ReviewError,
            "legacy-synthetic-value",
        ) as caught:
            self.validate(review, catalog=catalog)
        self.assertNotIn(LEGACY_A, str(caught.exception))

    def test_catalog_legacy_paths_stay_redacted_in_file_reader_errors(self) -> None:
        raw_value = "archived_" + "fixture_0001"
        catalog = legacy_catalog(values=(raw_value,))
        representations = (raw_value, legacy_value_base64(raw_value))
        variants = ["hardlink", "open-error", "writable"]
        if hasattr(os, "mkfifo"):
            variants.append("fifo")

        for representation in representations:
            for variant in variants:
                with self.subTest(representation=representation, variant=variant):
                    repo, base = self.new_repo(
                        {
                            "fixture.cfg": assignment_text(
                                "access_token",
                                raw_value,
                            ),
                            "safe.txt": "safe\n",
                        }
                    )
                    (repo / "README.md").write_text("head\n", encoding="utf-8")
                    head = self.commit(repo)
                    review = self.prepare(
                        repo=repo,
                        base=base,
                        head=head,
                        catalog=catalog,
                        exemptions=("historical-fixtures",),
                    )
                    target = review.workspace_root / f"moved-{representation}.txt"
                    (review.workspace_root / "safe.txt").rename(target)
                    patch_open = contextlib.nullcontext()
                    if variant == "hardlink":
                        os.link(
                            target,
                            review.workspace_root / f"peer-{representation}.txt",
                        )
                    elif variant == "open-error":
                        real_open = os.open

                        def fail_target_open(path, flags, *args, **kwargs):
                            if os.fspath(path) == os.fspath(target):
                                raise OSError(
                                    errno.EIO,
                                    f"synthetic failure at {target}",
                                )
                            return real_open(path, flags, *args, **kwargs)

                        patch_open = mock.patch.object(
                            workspace.os,
                            "open",
                            side_effect=fail_target_open,
                        )
                    elif variant == "writable":
                        target.chmod(0o664)
                    else:
                        target.unlink()
                        os.mkfifo(target, mode=0o600)

                    with patch_open, self.assertRaises(ReviewError) as caught:
                        self.validate(review, catalog=catalog)
                    message = str(caught.exception)
                    self.assertIn("<redacted snapshot path>", message)
                    self.assertNotIn(raw_value, message)
                    self.assertNotIn(legacy_value_base64(raw_value), message)

    def test_catalog_legacy_path_stays_redacted_after_a_read_error(self) -> None:
        raw_value = "archived_" + "fixture_0001"
        for representation in (raw_value, legacy_value_base64(raw_value)):
            with self.subTest(representation=representation):
                target = self.root / f"moved-{representation}.txt"
                target.write_text("safe\n", encoding="utf-8")
                with (
                    mock.patch.object(
                        workspace,
                        "_stream_secret_scan",
                        side_effect=OSError(
                            errno.EIO,
                            f"synthetic failure at {target}",
                        ),
                    ),
                    self.assertRaises(ReviewError) as caught,
                ):
                    workspace._file_secret_scan(
                        target,
                        diagnostic_path="<redacted snapshot path>",
                    )
                message = str(caught.exception)
                self.assertIn("<redacted snapshot path>", message)
                self.assertNotIn(raw_value, message)
                self.assertNotIn(legacy_value_base64(raw_value), message)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires FIFO support")
    def test_frozen_head_fifo_tampering_fails_without_blocking(self) -> None:
        repo, base = self.new_repo({"README.md": "base\n"})
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        review = self.prepare(repo=repo, base=base, head=head)
        frozen_file = review.workspace_root / "README.md"
        frozen_file.unlink()
        os.mkfifo(frozen_file, mode=0o600)
        with self.assertRaisesRegex(ReviewError, "not a regular file"):
            self.validate(review)

    def test_helper_private_control_state_blocks_artifact_tampering(self) -> None:
        replacements = {
            workspace.CHANGED_PATH_DIGESTS_NAME: b"tampered.txt\0",
            "changed-blob-findings.z": (b"head\0tampered.txt\0private-key\0"),
            workspace.SYNTHETIC_MANIFEST_NAME: b'{"entries":[]}\n',
            workspace.SYNTHETIC_CHANGED_EVIDENCE_NAME: (
                b'{"entries":[],"schema_version":1}\n'
            ),
            "review.diff": b"",
            "review.prompt": b"Review the frozen range.\n",
        }
        for artifact_name, replacement in replacements.items():
            with self.subTest(artifact=artifact_name):
                repo, base = self.new_repo(
                    {
                        "auth.json": assignment_text(
                            "access_token",
                            AUTHORING_VALUES[0],
                        ),
                        "fixture.cfg": assignment_text(
                            "password",
                            "ActualOpaqueSecretA9Z8Y7",
                        ),
                    }
                )
                (repo / "auth.json").unlink()
                (repo / "fixture.cfg").unlink()
                head = self.commit(repo)
                review = self.prepare(repo=repo, base=base, head=head)
                private_state = (
                    review.container_dir / workspace.CONTROL_ARTIFACT_STATE_NAME
                ).read_text(encoding="utf-8")
                self.assertFalse(AUTHORING_VALUES[0] in private_state)
                artifact = review.workspace_root / ".codex-review" / artifact_name
                artifact.write_bytes(replacement)
                with self.assertRaisesRegex(
                    ReviewError,
                    "helper-private control state",
                ):
                    self.validate(review)

    def test_review_control_directory_rejects_unbound_entries(self) -> None:
        variants = ["regular", "directory", "symlink"]
        if hasattr(os, "mkfifo"):
            variants.append("fifo")
        for variant in variants:
            with self.subTest(variant=variant):
                repo, base = self.new_repo({"README.md": "base\n"})
                (repo / "README.md").write_text("head\n", encoding="utf-8")
                head = self.commit(repo)
                review = self.prepare(repo=repo, base=base, head=head)
                control_dir = review.workspace_root / ".codex-review"
                extra = control_dir / "unvalidated.txt"
                if variant == "regular":
                    extra.write_text(
                        assignment_text(
                            "password",
                            "ActualOpaqueSecretA9Z8Y7",
                        ),
                        encoding="utf-8",
                    )
                elif variant == "directory":
                    extra.mkdir()
                    (extra / "nested.txt").write_text("nested\n", encoding="utf-8")
                elif variant == "symlink":
                    extra.symlink_to("review.prompt")
                else:
                    os.mkfifo(extra, mode=0o600)
                with self.assertRaisesRegex(
                    ReviewError,
                    "control directory entries are invalid",
                ):
                    self.validate(review)

    def test_helper_private_state_binds_control_directory_entry_set(self) -> None:
        repo, base = self.new_repo({"README.md": "base\n"})
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        review = self.prepare(repo=repo, base=base, head=head)
        state_path = review.container_dir / workspace.CONTROL_ARTIFACT_STATE_NAME
        payload = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(
            payload["directory"]["entry_count"],
            len(workspace.CONTROL_ARTIFACT_SPECS),
        )
        self.assertRegex(
            payload["directory"]["entry_names_sha256"],
            r"\A[0-9a-f]{64}\Z",
        )
        payload["directory"]["entry_names_sha256"] = "0" * 64
        state_path.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            ReviewError,
            "control directory state is invalid",
        ):
            self.validate(review)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires FIFO support")
    def test_changed_path_control_fifo_fails_without_blocking(self) -> None:
        repo, base = self.new_repo({"auth.json": "{}\n"})
        (repo / "auth.json").unlink()
        head = self.commit(repo)
        review = self.prepare(repo=repo, base=base, head=head)
        changed_paths = (
            review.workspace_root
            / ".codex-review"
            / workspace.CHANGED_PATH_DIGESTS_NAME
        )
        changed_paths.unlink()
        os.mkfifo(changed_paths, mode=0o600)
        with self.assertRaisesRegex(
            ReviewError,
            "helper-private control state|not a regular file",
        ):
            self.validate(review)

    def test_changed_path_digests_bind_helper_private_raw_paths(self) -> None:
        repo, base = self.new_repo({"README.md": "base\n"})
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        review = self.prepare(repo=repo, base=base, head=head)
        private_paths = review.container_dir / workspace.PRIVATE_CHANGED_PATHS_NAME
        private_paths.write_bytes(b"different.txt\0")

        with self.assertRaisesRegex(
            ReviewError,
            "digests do not match helper-private changed paths",
        ):
            self.validate(review)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires FIFO support")
    def test_helper_private_changed_path_fifo_fails_without_blocking(self) -> None:
        repo, base = self.new_repo({"README.md": "base\n"})
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        review = self.prepare(repo=repo, base=base, head=head)
        private_paths = review.container_dir / workspace.PRIVATE_CHANGED_PATHS_NAME
        private_paths.unlink()
        os.mkfifo(private_paths, mode=0o600)

        with self.assertRaisesRegex(ReviewError, "not a regular file"):
            self.validate(review)

    def test_manifest_count_tampering_cannot_authorize_a_head_copy(self) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        repo, base = self.new_repo(
            {"fixture.cfg": assignment_text("access_token", LEGACY_A)}
        )
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        review = self.prepare(
            repo=repo,
            base=base,
            head=head,
            catalog=catalog,
            exemptions=("historical-fixtures",),
        )
        manifest_path = (
            review.workspace_root / ".codex-review" / workspace.SYNTHETIC_MANIFEST_NAME
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["entries"][0]["base_count"] = 2
        manifest["entries"][0]["head_count"] = 2
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        (review.workspace_root / "copied.txt").write_text(
            f"plain text {LEGACY_A}\n",
            encoding="utf-8",
        )
        private_state = review.container_dir / workspace.SYNTHETIC_PRIVATE_MANIFEST_NAME
        private_contents = private_state.read_text(encoding="utf-8")
        self.assertNotIn(LEGACY_A, private_contents)
        self.assertNotIn(legacy_value_base64(LEGACY_A), private_contents)
        with self.assertRaisesRegex(
            ReviewError,
            "does not match helper-private control state",
        ):
            self.validate(review, catalog=catalog)

    def test_secret_reduction_manifest_tampering_fails_closed(self) -> None:
        cases = (
            ("range", "version or review range"),
            ("digest", "helper-private entry is inconsistent"),
            ("count", "count changed after preparation"),
            ("occurrence-commitment", "occurrence provenance changed"),
            ("private-base64", "not canonical Base64"),
        )
        for tamper, expected_message in cases:
            with self.subTest(tamper=tamper):
                fixture = reduction_fixture("generic-secret-assignment")
                repo, base = self.new_repo({"fixture.cfg": fixture * 2})
                (repo / "fixture.cfg").write_text(fixture, encoding="utf-8")
                head = self.commit(repo)
                review = self.prepare(repo=repo, base=base, head=head)
                control_dir = review.workspace_root / ".codex-review"
                public_path = control_dir / workspace.SYNTHETIC_MANIFEST_NAME
                private_path = (
                    review.container_dir / workspace.SYNTHETIC_PRIVATE_MANIFEST_NAME
                )
                public = json.loads(public_path.read_text(encoding="utf-8"))
                private = json.loads(private_path.read_text(encoding="utf-8"))
                self.assertEqual(public["schema_version"], 4)
                self.assertEqual(private["schema_version"], 4)
                self.assertEqual(len(private["secret_reduction_values"]), 1)

                if tamper == "range":
                    public["head_ref"] = "0" * 40
                    private["head_ref"] = "0" * 40
                elif tamper == "digest":
                    public["secret_reductions"][0]["value_sha256"] = "0" * 64
                    private["secret_reductions"][0]["value_sha256"] = "0" * 64
                    private["secret_reduction_values"][0]["value_sha256"] = "0" * 64
                elif tamper == "count":
                    for manifest in (public, private):
                        manifest["secret_reductions"][0]["base_count"] = 3
                        manifest["secret_reductions"][0]["head_count"] = 2
                elif tamper == "occurrence-commitment":
                    for manifest in (public, private):
                        manifest["secret_reduction_provenance"]["head_sha256"] = (
                            "0" * 64
                        )
                else:
                    private["secret_reduction_values"][0]["value_base64"] = "***"

                if tamper != "private-base64":
                    public_path.write_text(json.dumps(public), encoding="utf-8")
                private_path.write_text(json.dumps(private), encoding="utf-8")
                if tamper != "private-base64":
                    control_state = workspace._build_control_artifact_state(
                        control_dir=control_dir
                    )
                    state_path = (
                        review.container_dir / workspace.CONTROL_ARTIFACT_STATE_NAME
                    )
                    state_path.write_text(json.dumps(control_state), encoding="utf-8")

                with self.assertRaisesRegex(ReviewError, expected_message):
                    self.validate(review)

    def test_materialized_head_cannot_restore_a_reduced_secret(self) -> None:
        fixture = reduction_fixture("generic-secret-assignment")
        repo, base = self.new_repo({"fixture.cfg": fixture})
        (repo / "fixture.cfg").unlink()
        head = self.commit(repo)
        review = self.prepare(repo=repo, base=base, head=head)

        (review.workspace_root / "fixture.cfg").write_text(
            fixture,
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ReviewError, "count changed after preparation"):
            self.validate(review)

    def test_materialized_head_cannot_remove_a_residual_reduced_secret(self) -> None:
        fixture = reduction_fixture("generic-secret-assignment")
        repo, base = self.new_repo({"fixture.cfg": fixture * 2})
        (repo / "fixture.cfg").write_text(fixture, encoding="utf-8")
        head = self.commit(repo)
        review = self.prepare(repo=repo, base=base, head=head)

        (review.workspace_root / "fixture.cfg").unlink()
        with self.assertRaisesRegex(ReviewError, "count changed after preparation"):
            self.validate(review)

    def test_materialized_head_cannot_relocate_a_residual_reduced_secret(
        self,
    ) -> None:
        fixture = reduction_fixture("generic-secret-assignment")
        repo, base = self.new_repo({"fixture.cfg": fixture * 2})
        (repo / "fixture.cfg").write_text(fixture, encoding="utf-8")
        head = self.commit(repo)
        review = self.prepare(repo=repo, base=base, head=head)

        (review.workspace_root / "fixture.cfg").write_text(
            "# shifted\n" + fixture,
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ReviewError, "occurrence provenance changed"):
            self.validate(review)

    def test_overlapping_legacy_values_are_counted_independently(self) -> None:
        longer = LEGACY_A + "Suffix"
        catalog = legacy_catalog(values=(LEGACY_A, longer))
        repo, base = self.new_repo(
            {
                "fixture.cfg": (
                    assignment_text("access_token", LEGACY_A)
                    + assignment_text("refresh_token", longer)
                )
            }
        )
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        review = self.prepare(
            repo=repo,
            base=base,
            head=head,
            catalog=catalog,
            exemptions=("historical-fixtures",),
        )
        evidence = self.validate(review, catalog=catalog)
        counts = {
            entry["token_id"]: (
                entry["base_count"],
                entry["head_count"],
                entry["base_unembedded_count"],
                entry["head_unembedded_count"],
            )
            for entry in evidence["synthetic_tokens"]["legacy_counts"]
        }
        self.assertEqual(counts["historical-1"], (2, 2, 1, 1))
        self.assertEqual(counts["historical-2"], (1, 1, 1, 1))

    def test_embedded_legacy_value_cannot_become_standalone(self) -> None:
        longer = LEGACY_A + "Suffix"
        catalog = legacy_catalog(values=(LEGACY_A, longer))
        cases = {
            "assignment": (
                assignment_text("refresh_token", longer),
                assignment_text("access_token", LEGACY_A),
            ),
            "plain": (
                f"historical fixture: {longer}\n",
                f"historical fixture: {LEGACY_A}\n",
            ),
        }
        for label, (base_fixture, head_fixture) in cases.items():
            with self.subTest(case=label):
                repo, base = self.new_repo({"fixture.cfg": base_fixture})
                (repo / "fixture.cfg").write_text(
                    head_fixture,
                    encoding="utf-8",
                )
                head = self.commit(repo)
                with self.assertRaisesRegex(
                    ReviewError,
                    "unembedded count increased",
                ):
                    self.prepare(
                        repo=repo,
                        base=base,
                        head=head,
                        catalog=catalog,
                        exemptions=("historical-fixtures",),
                    )

    def test_reduced_dynamic_container_does_not_change_legacy_embedding(self) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        dynamic = "DynamicPrefixA9Z8" + LEGACY_A + "DynamicSuffixQ7W6"
        repo, base = self.new_repo(
            {"fixture.cfg": assignment_text("password", dynamic)}
        )
        (repo / "fixture.cfg").write_text(
            assignment_text("access_token", LEGACY_A),
            encoding="utf-8",
        )
        head = self.commit(repo)

        review = self.prepare(
            repo=repo,
            base=base,
            head=head,
            catalog=catalog,
            exemptions=("historical-fixtures",),
        )
        evidence = self.validate(review, catalog=catalog)
        legacy = evidence["synthetic_tokens"]["legacy_counts"]
        reductions = evidence["synthetic_tokens"]["secret_reductions"]
        self.assertEqual(len(legacy), 1)
        self.assertEqual(
            (
                legacy[0]["base_count"],
                legacy[0]["head_count"],
                legacy[0]["base_unembedded_count"],
                legacy[0]["head_unembedded_count"],
            ),
            (1, 1, 1, 1),
        )
        self.assertEqual(len(reductions), 1)
        self.assertEqual(
            (
                reductions[0]["base_count"],
                reductions[0]["head_count"],
                reductions[0]["base_unembedded_count"],
                reductions[0]["head_unembedded_count"],
            ),
            (1, 0, 1, 0),
        )

    def test_valid_long_provider_assignment_can_strictly_reduce(self) -> None:
        candidate = "sk-proj-B1" + "B" * 506
        fixture = assignment_text("api_token", candidate)
        repo, base = self.new_repo({"fixture.cfg": fixture * 2})
        (repo / "fixture.cfg").write_text(fixture, encoding="utf-8")
        head = self.commit(repo)

        review = self.prepare(repo=repo, base=base, head=head)
        evidence = self.validate(review)
        reductions = evidence["synthetic_tokens"]["secret_reductions"]
        self.assertEqual(len(reductions), 1)
        self.assertEqual(reductions[0]["rules"], ["openai-key"])
        self.assertEqual(
            (
                reductions[0]["base_count"],
                reductions[0]["head_count"],
                reductions[0]["base_unembedded_count"],
                reductions[0]["head_unembedded_count"],
            ),
            (2, 1, 2, 1),
        )

    def test_observed_legacy_value_must_not_overlap_authoring_pool(self) -> None:
        overlapping = AUTHORING_VALUES[0] + "_suffix"
        with self.assertRaisesRegex(ReviewError, "overlapping values"):
            legacy_catalog(values=(overlapping,))

    def test_non_ascii_legacy_value_fails_closed(self) -> None:
        non_ascii = LEGACY_A.replace(
            "A", "\N{LATIN CAPITAL LETTER A WITH RING ABOVE}", 1
        )
        with self.assertRaisesRegex(ReviewError, "exact ASCII"):
            legacy_catalog(values=(non_ascii,))

    def test_unknown_duplicate_unused_and_unselected_legacy_fail_closed(self) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        repo, base = self.new_repo({"README.md": "base\n"})
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        for selection, message in (
            (("missing",), "unknown synthetic secret exemption"),
            (("historical-fixtures",) * 2, "duplicate synthetic secret exemption"),
            (("historical-fixtures",), "unused"),
        ):
            with (
                self.subTest(selection=selection),
                self.assertRaisesRegex(ReviewError, message),
            ):
                self.prepare(
                    repo=repo,
                    base=base,
                    head=head,
                    catalog=catalog,
                    exemptions=selection,
                )

        secret_repo, secret_base = self.new_repo(
            {"fixture.cfg": f'access_token = "{LEGACY_A}"\n'}
        )
        (secret_repo / "README.md").write_text("head\n", encoding="utf-8")
        secret_head = self.commit(secret_repo)
        with self.assertRaisesRegex(ReviewError, "generic-secret-assignment"):
            self.prepare(
                repo=secret_repo,
                base=secret_base,
                head=secret_head,
                catalog=catalog,
            )

    def test_prompt_only_generic_secret_is_trusted_review_input(self) -> None:
        repo, base = self.new_repo({"README.md": "base\n"})
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        secret = reduction_secret("generic-secret-assignment").decode("ascii")
        prompt = self.root / "prompt-generic-secret-assignment.txt"
        prompt.write_text(
            "Review {review_range}\n" + reduction_fixture("generic-secret-assignment"),
            encoding="utf-8",
        )
        review = self.prepare(
            repo=repo,
            base=base,
            head=head,
            prompt_override=prompt,
        )
        evidence = self.validate(review)
        self.assertIn(secret, review.prompt_file.read_text(encoding="utf-8"))
        self.assertFalse(
            any(
                entry["surface"] == "review-prompt"
                for entry in evidence["synthetic_tokens"]["accepted"]
            )
        )

    def test_prompt_with_authoring_value_is_integrity_only(self) -> None:
        repo, base = self.new_repo({"README.md": "base\n"})
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        prompt = self.root / "prompt-authoring-value.txt"
        prompt.write_text(
            "Review {review_range}\n"
            + assignment_text("access_token", AUTHORING_VALUES[0]),
            encoding="utf-8",
        )
        review = self.prepare(
            repo=repo,
            base=base,
            head=head,
            prompt_override=prompt,
        )

        evidence = self.validate(review)
        encoded = json.dumps(evidence, sort_keys=True)
        self.assertNotIn(AUTHORING_VALUES[0], encoded)
        self.assertFalse(
            any(
                entry["surface"] == "review-prompt"
                for entry in evidence["synthetic_tokens"]["accepted"]
            )
        )
        self.assertIn(
            AUTHORING_VALUES[0],
            review.prompt_file.read_text(encoding="utf-8"),
        )

    def test_prompt_with_selected_legacy_value_is_trusted_input(self) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        repo, base = self.new_repo(
            {"fixture.cfg": assignment_text("access_token", LEGACY_A)}
        )
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        prompt = self.root / "prompt-selected-legacy.txt"
        prompt.write_text(
            f'Review {{review_range}}\naccess_token = "{LEGACY_A}"\n',
            encoding="utf-8",
        )
        review = self.prepare(
            repo=repo,
            base=base,
            head=head,
            catalog=catalog,
            exemptions=("historical-fixtures",),
            prompt_override=prompt,
        )
        evidence = self.validate(review, catalog=catalog)
        self.assertIn(LEGACY_A, review.prompt_file.read_text(encoding="utf-8"))
        self.assertFalse(
            any(
                entry["surface"] == "review-prompt"
                for entry in evidence["synthetic_tokens"]["accepted"]
            )
        )

    def test_strictly_reduced_tracked_secret_is_allowed_in_prompt(
        self,
    ) -> None:
        fixture = reduction_fixture("generic-secret-assignment")
        secret = reduction_secret("generic-secret-assignment").decode("ascii")
        repo, base = self.new_repo({"fixture.cfg": fixture * 2})
        (repo / "fixture.cfg").write_text(fixture, encoding="utf-8")
        head = self.commit(repo)
        prompt = self.root / "prompt-reduced-secret.txt"
        prompt.write_text(
            "Review {review_range}\n" + fixture,
            encoding="utf-8",
        )
        review = self.prepare(
            repo=repo,
            base=base,
            head=head,
            prompt_override=prompt,
        )
        evidence = self.validate(review)
        self.assertIn(secret, review.prompt_file.read_text(encoding="utf-8"))
        self.assertEqual(
            len(evidence["synthetic_tokens"]["secret_reductions"]),
            1,
        )
        self.assertFalse(
            any(
                entry["surface"] == "review-prompt"
                for entry in evidence["synthetic_tokens"]["accepted"]
            )
        )

    def test_audit_master_cli_verifies_pinned_provenance_without_raw_value(
        self,
    ) -> None:
        unrelated = "sk-" + "Q" * 40
        repo, first_commit = self.new_repo(
            {
                "fixture.cfg": (
                    assignment_text("password", unrelated)
                    + assignment_text("access_token", AUTHORING_VALUES[0])
                    + assignment_text("refresh_token", LEGACY_PRINTABLE)
                ),
                "notes.txt": f"historical literal: {LEGACY_PRINTABLE}\n",
            }
        )
        (repo / "fixture.cfg").write_text(
            assignment_text("password", unrelated)
            + assignment_text("access_token", AUTHORING_VALUES[0])
            + assignment_text("refresh_token", LEGACY_PRINTABLE)
            + assignment_text("id_token", LEGACY_B),
            encoding="utf-8",
        )
        tip = self.commit(repo)
        git(repo, "remote", "add", "origin", "https://github.com/example/project.git")
        payload = catalog_payload()
        payload["legacy_exemptions"] = [
            {
                "id": "historical-fixtures",
                "repository": "example/project",
                "verified_master_tip": tip,
                "match": "non-increasing-global-count",
                "values": [
                    {
                        "id": "historical-1",
                        "rule": "generic-secret-assignment",
                        "value_base64": legacy_value_base64(LEGACY_PRINTABLE),
                        "containing_commit": first_commit,
                        "source_occurrences": 2,
                    },
                    {
                        "id": "historical-2",
                        "rule": "generic-secret-assignment",
                        "value_base64": legacy_value_base64(LEGACY_B),
                        "containing_commit": tip,
                        "source_occurrences": 1,
                    },
                ],
            }
        ]
        catalog = synthetic_tokens.parse_catalog_bytes(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(cli, "load_catalog", return_value=catalog),
            mock.patch.object(workspace, "load_catalog", return_value=catalog),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = cli.main(
                [
                    "synthetic-tokens",
                    "audit-master",
                    "--repo",
                    str(repo),
                    "--ref",
                    tip,
                    "--exemption",
                    "historical-fixtures",
                ]
            )
        self.assertEqual((returncode, stderr.getvalue()), (0, ""))
        evidence = json.loads(stdout.getvalue())
        self.assertEqual(evidence["status"], "verified")
        self.assertEqual(evidence["values"][0]["source_occurrences"], 2)
        self.assertEqual(len(evidence["values"]), 2)
        self.assertNotIn(LEGACY_PRINTABLE, stdout.getvalue())
        self.assertNotIn(legacy_value_base64(LEGACY_PRINTABLE), stdout.getvalue())
        self.assertNotIn(LEGACY_B, stdout.getvalue())
        self.assertNotIn(unrelated, stdout.getvalue())

        (repo / "README.md").write_text("review head\n", encoding="utf-8")
        review_head = self.commit(repo, "Review head")
        with self.assertRaisesRegex(ReviewError, "openai-key"):
            self.prepare(
                repo=repo,
                base=tip,
                head=review_head,
                catalog=catalog,
                exemptions=("historical-fixtures",),
            )

        bad_payload = json.loads(json.dumps(payload))
        bad_payload["legacy_exemptions"][0]["values"][0]["source_occurrences"] = 1
        bad_catalog = synthetic_tokens.parse_catalog_bytes(
            json.dumps(bad_payload, separators=(",", ":")).encode("utf-8")
        )
        with (
            mock.patch.object(workspace, "load_catalog", return_value=bad_catalog),
            self.assertRaisesRegex(ReviewError, "occurrence evidence does not match"),
        ):
            workspace.audit_legacy_exemption(
                repo=repo,
                ref=tip,
                exemption=bad_catalog.legacy_exemption("historical-fixtures"),
            )

    def test_audit_master_counts_overlapping_provenance_values_independently(
        self,
    ) -> None:
        longer = LEGACY_A + "Suffix"
        repo, tip = self.new_repo(
            {
                "fixture.cfg": (
                    assignment_text("access_token", LEGACY_A)
                    + assignment_text("refresh_token", longer)
                )
            }
        )
        git(repo, "remote", "add", "origin", "https://github.com/example/project.git")
        payload = catalog_payload()
        payload["legacy_exemptions"] = [
            {
                "id": "historical-fixtures",
                "repository": "example/project",
                "verified_master_tip": tip,
                "match": "non-increasing-global-count",
                "values": [
                    {
                        "id": f"historical-{index}",
                        "rule": "generic-secret-assignment",
                        "value_base64": legacy_value_base64(value),
                        "containing_commit": tip,
                        "source_occurrences": 2 if index == 1 else 1,
                    }
                    for index, value in enumerate((LEGACY_A, longer), start=1)
                ],
            }
        ]
        catalog = synthetic_tokens.parse_catalog_bytes(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        with mock.patch.object(workspace, "load_catalog", return_value=catalog):
            evidence = workspace.audit_legacy_exemption(
                repo=repo,
                ref=tip,
                exemption=catalog.legacy_exemption("historical-fixtures"),
            )
        counts = {
            entry["token_id"]: entry["source_occurrences"]
            for entry in evidence["values"]
        }
        self.assertEqual(counts, {"historical-1": 2, "historical-2": 1})
        self.assertNotIn(LEGACY_A, json.dumps(evidence, sort_keys=True))
        self.assertNotIn(longer, json.dumps(evidence, sort_keys=True))

    def test_evidence_budget_rejects_a_new_key_before_insertion(self) -> None:
        counts: Counter[tuple[object, ...]] = Counter()
        for index in range(workspace.MAX_SYNTHETIC_EVIDENCE_ENTRIES):
            workspace._record_bounded_evidence_count(
                counts,
                (index,),
                1,
                reserved_entries=0,
                overflow_message="bounded",
            )
        workspace._record_bounded_evidence_count(
            counts,
            (0,),
            1,
            reserved_entries=0,
            overflow_message="bounded",
        )
        rejected_key = (workspace.MAX_SYNTHETIC_EVIDENCE_ENTRIES,)
        with self.assertRaisesRegex(ReviewError, "bounded"):
            workspace._record_bounded_evidence_count(
                counts,
                rejected_key,
                1,
                reserved_entries=0,
                overflow_message="bounded",
            )
        self.assertEqual(len(counts), workspace.MAX_SYNTHETIC_EVIDENCE_ENTRIES)
        self.assertEqual(counts[(0,)], 2)
        self.assertNotIn(rejected_key, counts)

    def test_changed_blob_evidence_budget_fails_during_insertion(self) -> None:
        repo, base = self.new_repo({"README.md": "base\n"})
        for index in range(3):
            (repo / f"fixture-{index}.cfg").write_text(
                assignment_text("access_token", AUTHORING_VALUES[0]),
                encoding="utf-8",
            )
        head = self.commit(repo)
        with (
            mock.patch.object(workspace, "MAX_SYNTHETIC_EVIDENCE_ENTRIES", 2),
            self.assertRaisesRegex(ReviewError, "changed-blob evidence has too many"),
        ):
            self.prepare(repo=repo, base=base, head=head)

    def test_external_evidence_budget_reserves_changed_blob_entries(self) -> None:
        repo, base = self.new_repo(
            {
                "deleted.cfg": assignment_text("access_token", AUTHORING_VALUES[0]),
                "unchanged.cfg": assignment_text("access_token", AUTHORING_VALUES[0]),
            }
        )
        (repo / "deleted.cfg").unlink()
        head = self.commit(repo)
        review = self.prepare(repo=repo, base=base, head=head)
        with (
            mock.patch.object(workspace, "MAX_SYNTHETIC_EVIDENCE_ENTRIES", 1),
            self.assertRaisesRegex(
                ReviewError,
                "accepted synthetic-token evidence has too many entries",
            ),
        ):
            self.validate(review)

    def test_tampered_or_oversized_evidence_fails_closed(self) -> None:
        repo, base = self.new_repo({"README.md": "base\n"})
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        review = self.prepare(repo=repo, base=base, head=head)
        evidence_path = (
            review.workspace_root
            / ".codex-review"
            / workspace.SYNTHETIC_CHANGED_EVIDENCE_NAME
        )
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        payload["entries"] = [{}] * (workspace.MAX_SYNTHETIC_EVIDENCE_ENTRIES + 1)
        evidence_path.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ReviewError, "helper-private control state"):
            self.validate(review)

        evidence_path.write_bytes(b"x" * (workspace.MAX_SYNTHETIC_EVIDENCE_BYTES + 1))
        with self.assertRaisesRegex(ReviewError, "size limit"):
            self.validate(review)


if __name__ == "__main__":
    unittest.main()
