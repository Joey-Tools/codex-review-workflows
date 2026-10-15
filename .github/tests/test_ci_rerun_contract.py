from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "ci_rerun_contract", ROOT / ".github/scripts/check_ci_rerun_contract.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CiRerunContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = (ROOT / ".github/ci-rerun-contract.json").read_bytes()
        self.workflow = (ROOT / ".github/workflows/ci.yml").read_bytes()
        self.contract = json.loads(self.raw)

    def check(self, contract: object) -> dict[str, object]:
        return MODULE.check_contract(json.dumps(contract).encode(), self.workflow)

    def test_checked_in_binding_does_not_authorize_mutation_or_recovery(self) -> None:
        result = MODULE.check_contract(self.raw, self.workflow)
        self.assertEqual(result["workflow_binding"], "matched")
        self.assertIs(result["mutation_authorized"], False)
        self.assertIs(result["automatic_recovery_authority"], False)

    def test_workflow_drift_requires_a_reviewed_declaration_update(self) -> None:
        for workflow in (b"", self.workflow + b"\n", self.workflow.replace(
            b"contents: read", b"contents: write"
        )):
            with self.subTest(workflow_length=len(workflow)):
                with self.assertRaises(ValueError):
                    MODULE.check_contract(self.raw, workflow)

    def test_other_operations_authorities_and_repository_are_rejected(self) -> None:
        for key, value in (
            ("operation", "existing-run-rerun-full"),
            ("operation", "workflow_dispatch"),
            ("authority", "automatic-recovery"),
            ("repeat_safety", "idempotent"),
            ("repository", "Joey-Tools/codex-private-workflows"),
            ("workflow_path", ".github/workflows/codex-review-gate.yml"),
            ("schema", "joey-tools-ci-rerun-v2"),
        ):
            with self.subTest(key=key, value=value):
                with self.assertRaises(ValueError):
                    self.check(dict(self.contract, **{key: value}))

    def test_retry_budget_requires_exact_integer_two(self) -> None:
        for value in (True, 1, 3, 2.0, "2", None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.check(dict(self.contract, maximum_run_attempt=value))

    def test_jobs_and_time_budgets_are_closed(self) -> None:
        original = self.contract["job_timeout_minutes"]
        variants = (
            {}, [], dict(original, release=5), dict(original, test=10),
            dict(original, test=True), dict(original, test=5.0),
            {key: value for key, value in original.items() if key != "test"},
        )
        for jobs in variants:
            with self.subTest(jobs=jobs):
                with self.assertRaises(ValueError):
                    self.check(dict(self.contract, job_timeout_minutes=jobs))

    def test_fields_are_closed(self) -> None:
        for contract in (
            None, [], {}, dict(self.contract, authorization=True),
            {key: value for key, value in self.contract.items()
             if key != "workflow_sha256"},
        ):
            with self.subTest(contract_type=type(contract).__name__):
                with self.assertRaises(ValueError):
                    self.check(contract)

    def test_duplicates_are_rejected_at_each_level(self) -> None:
        for raw in (
            b'{"schema":"x","schema":"y"}',
            b'{"job_timeout_minutes":{"test":5,"test":5}}',
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    MODULE.check_contract(raw, self.workflow)

    def test_digest_is_exact_lowercase_sha256(self) -> None:
        for digest in (None, True, "0" * 64, "a" * 63, "A" * 64, "a" * 64 + "\n"):
            with self.subTest(digest=digest):
                with self.assertRaises(ValueError):
                    self.check(dict(self.contract, workflow_sha256=digest))

    def test_inputs_have_a_byte_ceiling(self) -> None:
        for raw, workflow in (
            (b" " * (MODULE.MAX_BYTES + 1), self.workflow),
            (self.raw, b" " * (MODULE.MAX_BYTES + 1)),
        ):
            with self.assertRaises(ValueError):
                MODULE.check_contract(raw, workflow)


if __name__ == "__main__":
    unittest.main()
