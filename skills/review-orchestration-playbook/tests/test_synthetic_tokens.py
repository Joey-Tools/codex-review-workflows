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
        first_read = 1024 * 1024
        committed_end = first_read - workspace.STREAM_SCAN_OVERLAP
        candidate_start = committed_end - len(candidate)
        payload = (
            b"x" * (candidate_start - len(assignment_prefix))
            + assignment_prefix
            + candidate
            + b'"\nstate = "expired"\n'
            + b"x" * workspace.STREAM_SCAN_OVERLAP
        )
        scan = workspace._stream_secret_scan(
            io.BytesIO(payload),
            size=len(payload),
            accepted_values=(accepted,),
        )
        self.assertIsNone(scan.blocking_rule)
        self.assertEqual(scan.accepted_counts[accepted], 1)

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

        unsafe = workspace._scan_secret_value(
            assignment_bytes(b"refresh_token", accepted.value) + b' + "adjacent"\n',
            accepted_values=(accepted,),
            capture_accepted_candidates=True,
            _continue_after_blocking=True,
        )
        self.assertEqual(unsafe.blocking_rule, "generic-secret-assignment")
        self.assertFalse(unsafe.accepted_counts)
        self.assertFalse(unsafe.accepted_candidates)

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
            ("anthropic-key", b"sk-ant-", b"A"),
            ("openai-key", b"sk-proj-", b"B"),
            ("github-token", b"ghp_", b"C"),
            ("gitlab-token", b"glpat-", b"D"),
            ("pypi-token", b"pypi-", b"E"),
            ("slack-token", b"xoxb-", b"F"),
            ("stripe-live-key", b"sk_live_", b"G"),
        )
        for expected_rule, prefix, alphabet in cases:
            with self.subTest(rule=expected_rule):
                scan = workspace._scan_secret_value(prefix + alphabet * 4096)
                self.assertEqual(scan.blocking_rule, expected_rule)

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
        review = self.prepare(repo=repo, base=base, head=head)
        with self.assertRaisesRegex(ReviewError, "generic-secret-assignment") as raised:
            self.validate(review)
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

        unselected_review = self.prepare(
            repo=repo,
            base=base,
            head=head,
            catalog=catalog,
        )
        with self.assertRaisesRegex(ReviewError, "generic-secret-assignment"):
            self.validate(unselected_review, catalog=catalog)

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
        unknown_review = self.prepare(
            repo=unknown_repo,
            base=unknown_base,
            head=unknown_head,
            catalog=catalog,
            exemptions=("historical-fixtures",),
        )
        with self.assertRaisesRegex(ReviewError, "generic-secret-assignment"):
            self.validate(unknown_review, catalog=catalog)

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
            "changed-paths.z": b"",
            "changed-blob-findings.z": b"",
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
        changed_paths = review.workspace_root / ".codex-review/changed-paths.z"
        changed_paths.unlink()
        os.mkfifo(changed_paths, mode=0o600)
        with self.assertRaisesRegex(
            ReviewError,
            "helper-private control state|not a regular file",
        ):
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
        review = self.prepare(
            repo=secret_repo,
            base=secret_base,
            head=secret_head,
            catalog=catalog,
        )
        with self.assertRaisesRegex(ReviewError, "generic-secret-assignment"):
            self.validate(review, catalog=catalog)

    def test_prompt_does_not_accept_selected_legacy_values(self) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        repo, base = self.new_repo(
            {"fixture.cfg": assignment_text("access_token", LEGACY_A)}
        )
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        prompt = self.root / "prompt-generic-secret-assignment.txt"
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
        with self.assertRaisesRegex(ReviewError, "review.prompt"):
            self.validate(review, catalog=catalog)

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
        review = self.prepare(
            repo=repo,
            base=tip,
            head=review_head,
            catalog=catalog,
            exemptions=("historical-fixtures",),
        )
        with self.assertRaisesRegex(ReviewError, "openai-key"):
            self.validate(review, catalog=catalog)

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
            mock.patch.object(workspace, "MAX_SYNTHETIC_EVIDENCE_ENTRIES", 2),
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
