from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import cli, synthetic_tokens, workspace  # noqa: E402
from review_runtime.common import ReviewError  # noqa: E402


PUBLIC_VALUES = (
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
LEGACY_A = "HistoricalFixtureAccessA9Z8Y7"
LEGACY_B = "HistoricalFixtureRefreshB8Y7X6"
GITHUB_LEGACY = "ghp_" + "A" * 36
HIGH_ENTROPY = b"Aa9!" + b"Bb8@" + b"Cc7#" + b"Dd6$" + b"Ee5%"


def assignment_bytes(key: bytes, value: bytes) -> bytes:
    return key + b' = "' + value + b'"'


def assignment_text(key: str, value: str) -> str:
    return f'{key} = "{value}"\n'


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
                    "value_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
                    "value_length": len(value.encode("utf-8")),
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
        value=None,
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
        self.assertEqual(self.catalog.schema_version, 1)
        self.assertEqual(self.catalog.pool_version, "public-example-v1")
        self.assertEqual(
            tuple(token.value.decode("ascii") for token in self.catalog.authoring_tokens),
            PUBLIC_VALUES,
        )
        self.assertEqual(len({token.identifier for token in self.catalog.authoring_tokens}), 10)
        self.assertEqual(self.catalog.legacy_exemptions, ())

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

    def test_mutated_pool_values_remain_blocked(self) -> None:
        original = PUBLIC_VALUES[0]
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

    def test_provider_specific_legacy_acceptance_suppresses_duplicate_assignment(self) -> None:
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
            + b'"\n'
            + b"x" * workspace.STREAM_SCAN_OVERLAP
        )
        scan = workspace._stream_secret_scan(
            io.BytesIO(payload),
            size=len(payload),
            accepted_values=(accepted,),
        )
        self.assertIsNone(scan.blocking_rule)
        self.assertEqual(scan.accepted_counts[accepted], 1)

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
                "placeholder-concatenation",
                b'access_token = "placeholder_token" ' + adjacent_secret,
            ),
        )
        for label, payload in cases:
            with self.subTest(case=label):
                scan = workspace._scan_secret_value(
                    payload,
                    accepted_values=self.accepted,
                )
                self.assertEqual(scan.blocking_rule, "generic-secret-assignment")

        json_value = workspace._scan_secret_value(
            b'{"access_token": "'
            + accepted.value
            + b'", "state": "expired"}',
            accepted_values=self.accepted,
        )
        self.assertIsNone(json_value.blocking_rule)
        self.assertEqual(json_value.accepted_counts[accepted], 1)

        keyword_argument = workspace._scan_secret_value(
            b'configure(access_token = "'
            + accepted.value
            + b'", state = "expired")',
            accepted_values=self.accepted,
        )
        self.assertIsNone(keyword_argument.blocking_rule)
        self.assertEqual(keyword_argument.accepted_counts[accepted], 1)

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

    def test_dense_accepted_surface_fails_closed_at_the_event_limit(self) -> None:
        accepted = self.accepted[0]
        payload = b"\n".join(
            assignment_bytes(b"access_token", accepted.value) for _ in range(3)
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
        unicode_value["authoring_pool"]["tokens"][0]["value"] = "synthetic_\N{CYRILLIC SMALL LETTER O}_credential"
        cases["unicode"] = unicode_value
        control = catalog_payload()
        control["authoring_pool"]["tokens"][0]["value"] = "synthetic credential value"
        cases["control"] = control
        rule = catalog_payload()
        rule["authoring_pool"]["tokens"][0]["rule"] = "github-token"
        cases["rule"] = rule
        extra = catalog_payload()
        extra["unexpected"] = True
        cases["extra-field"] = extra

        for label, payload in cases.items():
            with self.subTest(case=label), self.assertRaises(ReviewError):
                self.parse(payload)

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

    def test_malformed_and_duplicate_legacy_entries_fail_closed(self) -> None:
        payload = catalog_payload()
        digest = hashlib.sha256(LEGACY_A.encode("ascii")).hexdigest()
        entry = {
            "id": "legacy-a",
            "rule": "generic-secret-assignment",
            "value_sha256": digest,
            "value_length": len(LEGACY_A),
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
        with self.assertRaisesRegex(ReviewError, "duplicate legacy digest"):
            self.parse(payload)

        for field, value in (
            ("value_sha256", "not-a-digest"),
            ("value_length", True),
            ("source_occurrences", 0),
            ("rule", "aws-access-key"),
        ):
            malformed = catalog_payload()
            malformed_entry = {**entry, field: value}
            malformed["legacy_exemptions"] = [
                {**envelope, "values": [malformed_entry]}
            ]
            with self.subTest(field=field), self.assertRaises(ReviewError):
                self.parse(malformed)

    def test_secure_loader_rejects_symlink_hardlink_fifo_and_writable_file(self) -> None:
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
        self.assertEqual(len(payload["tokens"]), 10)
        self.assertTrue(all("value" not in token for token in payload["tokens"]))
        for raw in PUBLIC_VALUES:
            self.assertNotIn(raw, output)

    def test_get_returns_only_the_explicitly_selected_raw_value(self) -> None:
        returncode, output, error = self.run_cli("get", "access-a", "--json")
        self.assertEqual((returncode, error), (0, ""))
        payload = json.loads(output)
        self.assertEqual(payload["token"]["value"], PUBLIC_VALUES[0])
        for raw in PUBLIC_VALUES[1:]:
            self.assertNotIn(raw, output)

    def test_list_exemptions_and_unknown_get(self) -> None:
        returncode, output, error = self.run_cli("list-exemptions", "--json")
        self.assertEqual((returncode, error), (0, ""))
        self.assertEqual(json.loads(output)["exemptions"], [])

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
            assignment_text("access_token", PUBLIC_VALUES[0]),
            encoding="utf-8",
        )
        head = self.commit(repo)
        review = self.prepare(repo=repo, base=base, head=head)
        evidence = self.validate(review)
        encoded = json.dumps(evidence, sort_keys=True)
        self.assertNotIn(PUBLIC_VALUES[0], encoded)
        accepted = evidence["synthetic_tokens"]["accepted"]
        self.assertTrue(accepted)
        self.assertTrue(all("value_sha256" in entry for entry in accepted))
        self.assertTrue(any(entry["token_id"] == "access-a" for entry in accepted))

    def test_pool_value_in_credential_path_remains_blocked(self) -> None:
        repo, base = self.new_repo({"README.md": "base\n"})
        (repo / "auth.json").write_text(
            json.dumps({"access_token": PUBLIC_VALUES[0]}),
            encoding="utf-8",
        )
        head = self.commit(repo)
        review = self.prepare(repo=repo, base=base, head=head)
        with self.assertRaisesRegex(ReviewError, "credential-path"):
            self.validate(review)

    def test_non_pool_synthetic_looking_value_in_unchanged_head_is_blocked(self) -> None:
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

    def test_github_legacy_assignment_uses_the_provider_specific_exemption(self) -> None:
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
                    f'access_token = "{LEGACY_A}"\n'
                    f'refresh_token = "{LEGACY_B}"\n'
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

    def test_overlapping_legacy_values_fail_closed(self) -> None:
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

        with self.assertRaisesRegex(ReviewError, "values overlap"):
            self.prepare(
                repo=repo,
                base=base,
                head=head,
                catalog=catalog,
                exemptions=("historical-fixtures",),
            )

    def test_non_ascii_legacy_value_fails_closed(self) -> None:
        non_ascii = LEGACY_A.replace("A", "\N{LATIN CAPITAL LETTER A WITH RING ABOVE}", 1)
        catalog = legacy_catalog(values=(non_ascii,))
        repo, base = self.new_repo(
            {"fixture.cfg": assignment_text("access_token", non_ascii)}
        )
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)

        with self.assertRaisesRegex(ReviewError, "visible ASCII"):
            self.prepare(
                repo=repo,
                base=base,
                head=head,
                catalog=catalog,
                exemptions=("historical-fixtures",),
            )

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
            with self.subTest(selection=selection), self.assertRaisesRegex(
                ReviewError, message
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

    def test_prompt_does_not_accept_selected_legacy_value(self) -> None:
        catalog = legacy_catalog(values=(LEGACY_A,))
        repo, base = self.new_repo(
            {"fixture.cfg": f'access_token = "{LEGACY_A}"\n'}
        )
        (repo / "README.md").write_text("head\n", encoding="utf-8")
        head = self.commit(repo)
        prompt = self.root / "prompt.txt"
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

    def test_audit_master_cli_verifies_pinned_provenance_without_raw_value(self) -> None:
        repo, tip = self.new_repo(
            {"fixture.cfg": f'access_token = "{LEGACY_A}"\n'}
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
                        "id": "historical-1",
                        "rule": "generic-secret-assignment",
                        "value_sha256": hashlib.sha256(
                            LEGACY_A.encode("ascii")
                        ).hexdigest(),
                        "value_length": len(LEGACY_A),
                        "containing_commit": tip,
                        "source_occurrences": 1,
                    }
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
        self.assertEqual(evidence["values"][0]["source_occurrences"], 1)
        self.assertNotIn(LEGACY_A, stdout.getvalue())

    def test_audit_master_rejects_overlapping_provenance_values(self) -> None:
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
                        "value_sha256": hashlib.sha256(value.encode("ascii")).hexdigest(),
                        "value_length": len(value),
                        "containing_commit": tip,
                        "source_occurrences": 1,
                    }
                    for index, value in enumerate((LEGACY_A, longer), start=1)
                ],
            }
        ]
        catalog = synthetic_tokens.parse_catalog_bytes(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )

        with (
            mock.patch.object(workspace, "load_catalog", return_value=catalog),
            self.assertRaisesRegex(ReviewError, "values overlap"),
        ):
            workspace.audit_legacy_exemption(
                repo=repo,
                ref=tip,
                exemption=catalog.legacy_exemption("historical-fixtures"),
            )

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
        with self.assertRaisesRegex(ReviewError, "entries are invalid"):
            self.validate(review)

        evidence_path.write_bytes(b"x" * (workspace.MAX_SYNTHETIC_EVIDENCE_BYTES + 1))
        with self.assertRaisesRegex(ReviewError, "size limit"):
            self.validate(review)


if __name__ == "__main__":
    unittest.main()
