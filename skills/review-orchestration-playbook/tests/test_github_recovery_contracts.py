from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import re
import unittest


SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
REFERENCES = SKILL_ROOT / "references"
FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def _normalize(value: str) -> str:
    return " ".join(value.split()).lower()


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _commit_set_sha256(commits: list[str]) -> str:
    return hashlib.sha256(
        b"".join(commit.encode("ascii") + b"\n" for commit in commits)
    ).hexdigest()


def _receipt_sha256(receipt: dict[str, object]) -> str:
    return _canonical_sha256(
        {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    )


class _RecoveryContractValidator:
    """Closed reference/test-only validator; not a production consumer."""

    def __init__(
        self,
        schema: dict[str, object],
        producer_receipt: dict[str, object],
        producer_receipt_fields: list[str],
        platform_observation: dict[str, object],
        dispatch_delivery_receipt: dict[str, object],
        expected_delivery_receipt_sha256: str,
    ) -> None:
        self.schema = schema
        self.fields = schema["closed_fields"]
        self.producer_receipt = copy.deepcopy(producer_receipt)
        self.producer_receipt_fields = producer_receipt_fields
        self.platform_observation = copy.deepcopy(platform_observation)
        self.dispatch_delivery_receipt = copy.deepcopy(dispatch_delivery_receipt)
        self.expected_delivery_receipt_sha256 = expected_delivery_receipt_sha256

    def _closed(self, value: object, profile: str) -> bool:
        return isinstance(value, dict) and set(value) == set(self.fields[profile])

    @staticmethod
    def _positive_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value > 0

    @staticmethod
    def _safe_path(value: object) -> bool:
        if not isinstance(value, str) or not value or "\\" in value:
            return False
        path = pathlib.PurePosixPath(value)
        return (
            not path.is_absolute()
            and path.as_posix() == value
            and all(part not in {"", ".", ".."} for part in path.parts)
        )

    def validate_preflight(self, contract: object) -> bool:
        if not self._closed(contract, "preflight_contract"):
            return False
        source = contract["source_descriptor"]
        anchor = contract["source_trust_anchor"]
        exclusion = contract["candidate_range_exclusion_receipt"]
        operation = contract["operation_intent"]
        repeat_safety = contract["repeat_safety"]
        implementation = contract["implementation_receipt_identity"]
        edges_receipt = contract["dependency_edge_resolution_receipt"]
        if (
            contract["owner"] != "parent-orchestrator"
            or contract["status"] != "complete"
            or contract["profile"] != "github-codex-recovery-operation-preflight-v1"
            or not isinstance(contract["repository"], str)
            or contract["repository"].count("/") != 1
            or not self._positive_int(contract["pull_request"])
            or not isinstance(contract["head_sha"], str)
            or FULL_SHA.fullmatch(contract["head_sha"]) is None
            or not self._closed(source, "source_descriptor")
            or not self._closed(anchor, "source_trust_anchor")
            or not self._closed(exclusion, "candidate_range_exclusion_receipt")
            or not self._closed(operation, "operation_intent")
            or not self._closed(repeat_safety, "repeat_safety")
            or not self._closed(implementation, "implementation_receipt_identity")
            or not self._closed(edges_receipt, "dependency_edge_resolution_receipt")
            or contract["preflight_sha256"]
            != _canonical_sha256(
                {
                    key: value
                    for key, value in contract.items()
                    if key != "preflight_sha256"
                }
            )
        ):
            return False

        if (
            not isinstance(source["source_repository"], str)
            or source["source_repository"].count("/") != 1
            or FULL_SHA.fullmatch(source["source_commit"]) is None
            or not self._safe_path(source["source_path"])
            or SHA256.fullmatch(source["source_sha256"]) is None
            or anchor["owner"] != "parent-orchestrator"
            or anchor["status"] != "complete"
            or anchor["profile"] != "github-codex-recovery-source-trust-anchor-v1"
            or anchor["kind"]
            not in {
                "target-branch-baseline",
                "installed-trusted-release",
                "parent-fixed-external",
            }
            or anchor["identity"]
            != (
                f"{source['source_repository']}@{source['source_commit']}:"
                f"{source['source_path']}"
            )
            or anchor["sha256"] != source["source_sha256"]
            or anchor["repository"] != contract["repository"]
            or anchor["head_sha"] != contract["head_sha"]
            or FULL_SHA.fullmatch(anchor["base_sha"]) is None
        ):
            return False

        commits = exclusion["candidate_commits"]
        if (
            exclusion["owner"] != "parent-orchestrator"
            or exclusion["status"] != "complete"
            or exclusion["profile"]
            != "github-codex-recovery-candidate-range-exclusion-v1"
            or exclusion["repository"] != contract["repository"]
            or exclusion["base_sha"] != anchor["base_sha"]
            or exclusion["head_sha"] != contract["head_sha"]
            or exclusion["source"] != source
            or not isinstance(commits, list)
            or not commits
            or any(
                not isinstance(commit, str) or FULL_SHA.fullmatch(commit) is None
                for commit in commits
            )
            or commits != sorted(commits)
            or len(commits) != len(set(commits))
            or contract["head_sha"] not in commits
            or exclusion["base_sha"] in commits
            or not isinstance(exclusion["candidate_commit_count"], int)
            or isinstance(exclusion["candidate_commit_count"], bool)
            or exclusion["candidate_commit_count"] != len(commits)
            or exclusion["candidate_commits_sha256"] != _commit_set_sha256(commits)
            or (
                source["source_repository"] == contract["repository"]
                and source["source_commit"] in commits
            )
        ):
            return False

        producer = self.producer_receipt
        expected_implementation_identity = {
            "profile": producer["profile"],
            "receipt_sha256": producer["receipt_sha256"],
            "provider_kind": producer["provider_kind"],
            "workflow_sha": producer["workflow_sha"],
            "workflow_id": producer["workflow_id"],
            "run_id": producer["run_id"],
            "run_ref": producer["run_ref"],
            "head_sha": producer["feature_head_sha"],
        }
        if (
            set(producer) != set(self.producer_receipt_fields)
            or producer["owner"] != "parent-orchestrator"
            or producer["status"] != "complete"
            or producer["receipt_sha256"] != _receipt_sha256(producer)
            or producer["implementation_closure_complete"] is not True
            or producer["provider_kind"] != "github-actions"
            or producer["attestation_source"] != "github-actions-api"
            or producer["implementation_closure_count"]
            != len(producer["implementation_closure"])
            or producer["implementation_closure_sha256"]
            != _canonical_sha256(producer["implementation_closure"])
            or implementation != expected_implementation_identity
            or implementation["profile"]
            != "github-codex-merge-status-producer-implementation-v1"
            or SHA256.fullmatch(implementation["receipt_sha256"]) is None
            or implementation["provider_kind"] not in {"github-actions", "external-app"}
            or FULL_SHA.fullmatch(implementation["workflow_sha"]) is None
            or repeat_safety["declaration"] not in {"idempotent", "reentrant"}
            or repeat_safety["authorization_independent"] is not True
            or repeat_safety["operation_identity_sha256"]
            != _canonical_sha256(operation)
        ):
            return False

        closure_hashes = {
            item["blob_sha256"] for item in producer["implementation_closure"]
        }
        workflow_entries = [
            item
            for item in producer["implementation_closure"]
            if item["kind"] == "workflow"
            and item["repository"] == producer["workflow_repository"]
            and item["commit"] == producer["workflow_sha"]
            and item["path"] == producer["workflow_path"]
        ]
        edges = edges_receipt["resolved_edges"]
        if (
            edges_receipt["owner"] != "parent-orchestrator"
            or edges_receipt["status"] != "complete"
            or edges_receipt["profile"]
            != "github-codex-recovery-dependency-edge-resolution-v1"
            or edges_receipt["implementation_receipt_sha256"]
            != producer["receipt_sha256"]
            or edges_receipt["repository"] != contract["repository"]
            or edges_receipt["head_sha"] != contract["head_sha"]
            or len(workflow_entries) != 1
            or edges_receipt["workflow_entry_sha256"]
            != workflow_entries[0]["blob_sha256"]
            or not isinstance(edges, list)
            or any(
                not self._closed(edge, "dependency_edge")
                or edge["caller_entry_sha256"] not in closure_hashes
                or edge["callee_entry_sha256"] not in closure_hashes
                or not isinstance(edge["reference"], str)
                or not edge["reference"]
                for edge in edges
            )
            or edges
            != sorted(
                edges,
                key=lambda edge: (
                    edge["caller_entry_sha256"],
                    edge["reference"],
                    edge["callee_entry_sha256"],
                ),
            )
            or edges_receipt["resolved_edge_count"] != len(edges)
            or edges_receipt["resolved_edges_sha256"] != _canonical_sha256(edges)
            or edges_receipt["complete"] is not True
            or edges_receipt["receipt_sha256"] != _receipt_sha256(edges_receipt)
        ):
            return False

        inputs = operation["inputs"]
        if (
            operation["kind"] not in {"existing-run-rerun", "guarded-dispatch"}
            or not self._positive_int(operation["workflow_id"])
            or operation["workflow_id"] != producer["workflow_id"]
            or not isinstance(operation["ref"], str)
            or not operation["ref"]
            or not isinstance(inputs, list)
            or any(
                not self._closed(item, "input")
                or not isinstance(item["name"], str)
                or not item["name"]
                or not isinstance(item["value"], str)
                for item in inputs
            )
            or [item["name"] for item in inputs]
            != sorted(item["name"] for item in inputs)
            or len({item["name"] for item in inputs}) != len(inputs)
            or not self._closed(operation["expected_head_gate"], "expected_head_gate")
            or producer["feature_head_sha"] != contract["head_sha"]
        ):
            return False

        gate = operation["expected_head_gate"]
        if operation["kind"] == "existing-run-rerun":
            return (
                operation["run_id"] == producer["run_id"]
                and operation["ref"] == producer["run_ref"]
                and not inputs
                and gate
                == {
                    "status": "not-applicable",
                    "input_name": None,
                    "expected_head_sha": None,
                    "live_head_source": None,
                    "pre_side_effect": False,
                    "mismatch_behavior": None,
                    "implementation_entry_sha256": None,
                }
            )
        return (
            operation["run_id"] is None
            and operation["ref"].startswith("refs/heads/")
            and inputs == [{"name": "expected_head_sha", "value": contract["head_sha"]}]
            and gate
            == {
                "status": "verified",
                "input_name": "expected_head_sha",
                "expected_head_sha": contract["head_sha"],
                "live_head_source": "selected-pr-live-head",
                "pre_side_effect": True,
                "mismatch_behavior": "abort-before-side-effects",
                "implementation_entry_sha256": edges_receipt["workflow_entry_sha256"],
            }
        )

    def validate_completion(
        self, completion: object, accepted_preflight: dict[str, object]
    ) -> bool:
        if not self.validate_preflight(accepted_preflight) or not self._closed(
            completion, "completion_receipt"
        ):
            return False
        operation = accepted_preflight["operation_intent"]
        producer = self.producer_receipt
        observation = self.platform_observation
        delivery = self.dispatch_delivery_receipt
        run_object = (
            observation.get("run_object") if isinstance(observation, dict) else None
        )
        if (
            not self._closed(delivery, "dispatch_delivery_receipt")
            or delivery["owner"] != "parent-orchestrator"
            or delivery["status"] != "complete"
            or delivery["profile"] != "github-codex-dispatch-delivery-receipt-v1"
            or delivery["repository"] != accepted_preflight["repository"]
            or delivery["api_version"] != "2026-03-10"
            or delivery["http_method"] != "POST"
            or delivery["request_body_encoding"] != "rfc8785-semantic-json-v1"
            or delivery["request_body_sha256"]
            != _canonical_sha256(delivery["request_body"])
            or not isinstance(delivery["request_server_time"], str)
            or not delivery["request_server_time"]
            or delivery["delivery_status"]
            not in {"provider-returned-run-id", "existing-run-lineage"}
            or not self._positive_int(delivery["returned_run_id"])
            or delivery["unique_run_id"] != delivery["returned_run_id"]
            or delivery["receipt_sha256"] != _receipt_sha256(delivery)
            or delivery["receipt_sha256"] != self.expected_delivery_receipt_sha256
            or not self._closed(
                observation, "platform_dispatch_run_observation_receipt"
            )
            or observation["owner"] != "parent-orchestrator"
            or observation["status"] != "complete"
            or observation["profile"]
            != "github-codex-platform-dispatch-run-observation-v1"
            or observation["query_repository"] != accepted_preflight["repository"]
            or observation["query_endpoint"]
            != f"/repos/{accepted_preflight['repository']}/actions/runs/{observation['returned_run_id']}"
            or observation["preflight_sha256"] != accepted_preflight["preflight_sha256"]
            or observation["operation_identity_sha256"]
            != accepted_preflight["repeat_safety"]["operation_identity_sha256"]
            or observation["dispatch_delivery_receipt_sha256"]
            != delivery["receipt_sha256"]
            or observation["request_delivery_status"] != "proved-delivered"
            or not self._positive_int(observation["returned_run_id"])
            or observation["returned_run_id"] != delivery["returned_run_id"]
            or not self._closed(run_object, "platform_dispatch_run_object")
            or run_object["id"] != observation["returned_run_id"]
            or observation["run_object_sha256"] != _canonical_sha256(run_object)
            or not self._closed(observation["platform_identity"], "platform_identity")
            or observation["platform_identity"]
            != {"source": "github-actions-api", "authenticated": True}
            or observation["receipt_sha256"] != _receipt_sha256(observation)
        ):
            return False
        if operation["kind"] == "existing-run-rerun":
            expected_run_id = operation["run_id"]
            if (
                delivery["delivery_status"] != "existing-run-lineage"
                or delivery["request_endpoint"]
                != f"/repos/{accepted_preflight['repository']}/actions/runs/{expected_run_id}/rerun"
                or delivery["request_body"] != {}
                or delivery["response_status"] is not None
                or delivery["response"] is not None
                or delivery["response_sha256"] is not None
            ):
                return False
        else:
            expected_run_id = observation["returned_run_id"]
            response = delivery["response"]
            inputs_object = {
                item["name"]: item["value"] for item in operation["inputs"]
            }
            semantic_body = {"ref": operation["ref"], "inputs": inputs_object}
            if (
                delivery["delivery_status"] != "provider-returned-run-id"
                or delivery["request_endpoint"]
                != f"/repos/{accepted_preflight['repository']}/actions/workflows/{operation['workflow_id']}/dispatches"
                or not operation["inputs"]
                or not self._closed(delivery["request_body"], "dispatch_request_body")
                or delivery["request_body"] != semantic_body
                or delivery["response_status"] != 200
                or not self._closed(response, "dispatch_response")
                or response["workflow_run_id"] != delivery["returned_run_id"]
                or response["workflow_run_id"] != delivery["unique_run_id"]
                or response["workflow_run_id"] != observation["returned_run_id"]
                or response["run_url"]
                != f"https://api.github.com/repos/{accepted_preflight['repository']}/actions/runs/{response['workflow_run_id']}"
                or response["html_url"]
                != f"https://github.com/{accepted_preflight['repository']}/actions/runs/{response['workflow_run_id']}"
                or delivery["response_sha256"] != _canonical_sha256(response)
            ):
                return False
        return (
            completion["owner"] == "parent-orchestrator"
            and completion["status"] == "complete"
            and completion["profile"] == "github-codex-recovery-operation-completion-v1"
            and completion["preflight_sha256"] == accepted_preflight["preflight_sha256"]
            and self._positive_int(completion["returned_run_id"])
            and completion["returned_run_id"] == expected_run_id
            and completion["returned_run_id"] == observation["returned_run_id"]
            and completion["observed_repository"]
            == run_object["repository"]
            == accepted_preflight["repository"]
            and completion["observed_head_sha"]
            == run_object["head_sha"]
            == accepted_preflight["head_sha"]
            and completion["observed_workflow_id"]
            == run_object["workflow_id"]
            == operation["workflow_id"]
            and completion["observed_workflow_sha"]
            == run_object["workflow_sha"]
            == producer["workflow_sha"]
            and completion["observed_workflow_ref"]
            == run_object["workflow_ref"]
            == producer["workflow_ref"]
            and completion["observed_run_ref"]
            == run_object["run_ref"]
            == operation["ref"]
            and completion["observed_job_workflow_ref"]
            == run_object["job_workflow_ref"]
            == producer["job_workflow_ref"]
            and completion["completion_sha256"]
            == _canonical_sha256(
                {
                    key: value
                    for key, value in completion.items()
                    if key != "completion_sha256"
                }
            )
        )


class GitHubRecoveryContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.skill = _read(SKILL_ROOT / "SKILL.md")
        cls.probes = _read(REFERENCES / "github-pr-probes.md")
        cls.authority = _read(REFERENCES / "github-codex-evidence-authority.md")
        cls.contracts = _read(REFERENCES / "review-lane-contracts.md")
        cls.prompts = _read(REFERENCES / "review-prompt-templates.md")
        cls.readiness = _read(REFERENCES / "pr-readiness.md")
        cls.carriers = json.loads(
            _read(REFERENCES / "github-codex-terminal-carriers-v1.json")
        )
        cls.recovery_schema = cls.carriers["recovery_operation_contract_schema"]
        producer_closure = [
            {
                "repository": "octo/recovery-policy",
                "commit": "2" * 40,
                "path": ".github/workflows/recovery.yml",
                "blob_sha256": "7" * 64,
                "kind": "workflow",
            }
        ]
        cls.producer_receipt = {
            "owner": "parent-orchestrator",
            "status": "complete",
            "profile": "github-codex-merge-status-producer-implementation-v1",
            "provider_kind": "github-actions",
            "attestation_source": "github-actions-api",
            "repository": "octo/review-fixture",
            "feature_head_sha": "0" * 40,
            "run_ref": "refs/heads/feature/review",
            "run_id": 801,
            "run_attempt": 1,
            "check_suite_id": 601,
            "check_run_id": 701,
            "workflow_id": 901,
            "workflow_repository": "octo/recovery-policy",
            "workflow_path": ".github/workflows/recovery.yml",
            "workflow_sha": "2" * 40,
            "workflow_ref": (
                "octo/recovery-policy/.github/workflows/recovery.yml@refs/heads/feature/review"
            ),
            "workflow_ref_identity": {
                "repository": "octo/recovery-policy",
                "path": ".github/workflows/recovery.yml",
                "ref": "refs/heads/feature/review",
                "resolved_commit": "2" * 40,
                "entry": copy.deepcopy(producer_closure[0]),
                "entry_sha256": _canonical_sha256(producer_closure[0]),
            },
            "job_workflow_ref": (
                "octo/recovery-policy/.github/workflows/recovery.yml@refs/heads/feature/review"
            ),
            "job_workflow_ref_identity": {
                "repository": "octo/recovery-policy",
                "path": ".github/workflows/recovery.yml",
                "ref": "refs/heads/feature/review",
                "resolved_commit": "2" * 40,
                "entry": copy.deepcopy(producer_closure[0]),
                "entry_sha256": _canonical_sha256(producer_closure[0]),
            },
            "external_implementation_id": None,
            "implementation_closure_complete": True,
            "implementation_closure": producer_closure,
            "implementation_closure_count": 1,
            "implementation_closure_sha256": _canonical_sha256(producer_closure),
            "receipt_sha256": "",
        }
        cls.producer_receipt["receipt_sha256"] = _receipt_sha256(cls.producer_receipt)
        cls.implementation_identity = {
            "profile": cls.producer_receipt["profile"],
            "receipt_sha256": cls.producer_receipt["receipt_sha256"],
            "provider_kind": cls.producer_receipt["provider_kind"],
            "workflow_sha": cls.producer_receipt["workflow_sha"],
            "workflow_id": cls.producer_receipt["workflow_id"],
            "run_id": cls.producer_receipt["run_id"],
            "run_ref": cls.producer_receipt["run_ref"],
            "head_sha": cls.producer_receipt["feature_head_sha"],
        }
        head_sha = "0" * 40
        base_sha = "c" * 40
        candidate_commits = sorted([head_sha, "d" * 40])
        source = {
            "source_repository": "octo/recovery-policy",
            "source_commit": "2" * 40,
            "source_path": "contracts/recovery-operation-v1.json",
            "source_sha256": "3" * 64,
        }
        operation = {
            "kind": "existing-run-rerun",
            "workflow_id": 901,
            "run_id": 801,
            "ref": "refs/heads/feature/review",
            "inputs": [],
            "expected_head_gate": {
                "status": "not-applicable",
                "input_name": None,
                "expected_head_sha": None,
                "live_head_source": None,
                "pre_side_effect": False,
                "mismatch_behavior": None,
                "implementation_entry_sha256": None,
            },
        }
        edge_receipt = {
            "owner": "parent-orchestrator",
            "status": "complete",
            "profile": "github-codex-recovery-dependency-edge-resolution-v1",
            "implementation_receipt_sha256": cls.producer_receipt["receipt_sha256"],
            "repository": "octo/review-fixture",
            "head_sha": head_sha,
            "workflow_entry_sha256": "7" * 64,
            "resolved_edges": [],
            "resolved_edge_count": 0,
            "resolved_edges_sha256": _canonical_sha256([]),
            "complete": True,
            "receipt_sha256": "",
        }
        edge_receipt["receipt_sha256"] = _receipt_sha256(edge_receipt)
        cls.recovery_contract = {
            "owner": "parent-orchestrator",
            "status": "complete",
            "profile": "github-codex-recovery-operation-preflight-v1",
            "source_descriptor": source,
            "source_trust_anchor": {
                "owner": "parent-orchestrator",
                "status": "complete",
                "profile": "github-codex-recovery-source-trust-anchor-v1",
                "kind": "parent-fixed-external",
                "identity": (
                    "octo/recovery-policy@"
                    f"{'2' * 40}:contracts/recovery-operation-v1.json"
                ),
                "sha256": "3" * 64,
                "repository": "octo/review-fixture",
                "base_sha": base_sha,
                "head_sha": head_sha,
            },
            "candidate_range_exclusion_receipt": {
                "owner": "parent-orchestrator",
                "status": "complete",
                "profile": "github-codex-recovery-candidate-range-exclusion-v1",
                "repository": "octo/review-fixture",
                "base_sha": base_sha,
                "head_sha": head_sha,
                "source": copy.deepcopy(source),
                "candidate_commits": candidate_commits,
                "candidate_commit_count": len(candidate_commits),
                "candidate_commits_sha256": _commit_set_sha256(candidate_commits),
            },
            "repository": "octo/review-fixture",
            "pull_request": 7,
            "head_sha": head_sha,
            "operation_intent": operation,
            "repeat_safety": {
                "declaration": "reentrant",
                "operation_identity_sha256": _canonical_sha256(operation),
                "authorization_independent": True,
            },
            "implementation_receipt_identity": copy.deepcopy(
                cls.implementation_identity
            ),
            "dependency_edge_resolution_receipt": edge_receipt,
            "preflight_sha256": "",
        }
        cls.recovery_contract["preflight_sha256"] = _canonical_sha256(
            {
                key: value
                for key, value in cls.recovery_contract.items()
                if key != "preflight_sha256"
            }
        )
        cls.completion_receipt = {
            "owner": "parent-orchestrator",
            "status": "complete",
            "profile": "github-codex-recovery-operation-completion-v1",
            "preflight_sha256": cls.recovery_contract["preflight_sha256"],
            "returned_run_id": 801,
            "observed_repository": "octo/review-fixture",
            "observed_head_sha": head_sha,
            "observed_workflow_id": 901,
            "observed_workflow_sha": "2" * 40,
            "observed_workflow_ref": cls.producer_receipt["workflow_ref"],
            "observed_run_ref": "refs/heads/feature/review",
            "observed_job_workflow_ref": cls.producer_receipt["job_workflow_ref"],
            "completion_sha256": "",
        }
        cls.completion_receipt["completion_sha256"] = _canonical_sha256(
            {
                key: value
                for key, value in cls.completion_receipt.items()
                if key != "completion_sha256"
            }
        )
        run_object = {
            "id": 801,
            "repository": "octo/review-fixture",
            "head_sha": head_sha,
            "workflow_id": 901,
            "workflow_sha": "2" * 40,
            "workflow_ref": cls.producer_receipt["workflow_ref"],
            "run_ref": "refs/heads/feature/review",
            "job_workflow_ref": cls.producer_receipt["job_workflow_ref"],
        }
        cls.dispatch_delivery_receipt = {
            "owner": "parent-orchestrator",
            "status": "complete",
            "profile": "github-codex-dispatch-delivery-receipt-v1",
            "repository": "octo/review-fixture",
            "api_version": "2026-03-10",
            "http_method": "POST",
            "request_endpoint": "/repos/octo/review-fixture/actions/runs/801/rerun",
            "request_body": {},
            "request_body_encoding": "rfc8785-semantic-json-v1",
            "request_body_sha256": _canonical_sha256({}),
            "request_server_time": "2026-08-26T10:00:00Z",
            "delivery_status": "existing-run-lineage",
            "response_status": None,
            "response": None,
            "response_sha256": None,
            "returned_run_id": 801,
            "unique_run_id": 801,
            "receipt_sha256": "",
        }
        cls.dispatch_delivery_receipt["receipt_sha256"] = _receipt_sha256(
            cls.dispatch_delivery_receipt
        )
        cls.platform_observation = {
            "owner": "parent-orchestrator",
            "status": "complete",
            "profile": "github-codex-platform-dispatch-run-observation-v1",
            "query_repository": "octo/review-fixture",
            "query_endpoint": "/repos/octo/review-fixture/actions/runs/801",
            "preflight_sha256": cls.recovery_contract["preflight_sha256"],
            "operation_identity_sha256": cls.recovery_contract["repeat_safety"][
                "operation_identity_sha256"
            ],
            "dispatch_delivery_receipt_sha256": cls.dispatch_delivery_receipt[
                "receipt_sha256"
            ],
            "request_delivery_status": "proved-delivered",
            "returned_run_id": 801,
            "run_object": run_object,
            "run_object_sha256": _canonical_sha256(run_object),
            "platform_identity": {
                "source": "github-actions-api",
                "authenticated": True,
            },
            "receipt_sha256": "",
        }
        cls.platform_observation["receipt_sha256"] = _receipt_sha256(
            cls.platform_observation
        )
        cls.recovery_validator = _RecoveryContractValidator(
            cls.recovery_schema,
            cls.producer_receipt,
            cls.carriers["required_report_schema"]["parent_input_profiles"][
                "merge_status_producer_implementation_receipt"
            ],
            cls.platform_observation,
            cls.dispatch_delivery_receipt,
            cls.dispatch_delivery_receipt["receipt_sha256"],
        )

    def test_recovery_operation_contract_is_versioned_closed_and_head_bound(
        self,
    ) -> None:
        self.assertEqual(
            self.recovery_schema["schema"],
            "github-codex-recovery-operation-two-phase-v1",
        )
        self.assertEqual(
            self.recovery_schema["role"], "machine-readable-reference-and-test-only"
        )
        self.assertEqual(self.recovery_schema["production_consumer"], "out-of-scope")
        self.assertTrue(
            self.recovery_validator.validate_preflight(self.recovery_contract)
        )
        self.assertTrue(
            self.recovery_validator.validate_completion(
                self.completion_receipt, self.recovery_contract
            )
        )

        mutations = {
            "extra-field": lambda contract: contract.update(extra=True),
            "wrong-owner": lambda contract: contract.update(owner="candidate"),
            "wrong-head-type": lambda contract: contract.update(head_sha=1),
            "operation-ref-drift": lambda contract: contract["operation_intent"].update(
                ref="refs/heads/other"
            ),
            "implementation-drift": lambda contract: contract[
                "implementation_receipt_identity"
            ].update(receipt_sha256="9" * 64),
            "comment-creation": lambda contract: contract["operation_intent"].update(
                kind="create-comment"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                contract = copy.deepcopy(self.recovery_contract)
                mutate(contract)
                self.assertFalse(self.recovery_validator.validate_preflight(contract))

        candidate_source = copy.deepcopy(self.recovery_contract)
        source = candidate_source["source_descriptor"]
        source.update(
            source_repository=candidate_source["repository"],
            source_commit="d" * 40,
            source_sha256="4" * 64,
        )
        candidate_source["source_trust_anchor"].update(
            kind="installed-trusted-release",
            identity=(
                f"{candidate_source['repository']}@{'d' * 40}:"
                "contracts/recovery-operation-v1.json"
            ),
            sha256="4" * 64,
        )
        candidate_source["candidate_range_exclusion_receipt"]["source"] = copy.deepcopy(
            source
        )
        candidate_source["preflight_sha256"] = _canonical_sha256(
            {k: v for k, v in candidate_source.items() if k != "preflight_sha256"}
        )
        self.assertFalse(self.recovery_validator.validate_preflight(candidate_source))

        guarded = copy.deepcopy(self.recovery_contract)
        guarded_operation = guarded["operation_intent"]
        guarded_operation.update(
            kind="guarded-dispatch",
            run_id=None,
            ref="refs/heads/feature/review",
            inputs=[
                {
                    "name": "expected_head_sha",
                    "value": guarded["head_sha"],
                }
            ],
            expected_head_gate={
                "status": "verified",
                "input_name": "expected_head_sha",
                "expected_head_sha": guarded["head_sha"],
                "live_head_source": "selected-pr-live-head",
                "pre_side_effect": True,
                "mismatch_behavior": "abort-before-side-effects",
                "implementation_entry_sha256": "7" * 64,
            },
        )
        guarded["repeat_safety"]["operation_identity_sha256"] = _canonical_sha256(
            guarded_operation
        )
        guarded["preflight_sha256"] = _canonical_sha256(
            {k: v for k, v in guarded.items() if k != "preflight_sha256"}
        )
        self.assertTrue(self.recovery_validator.validate_preflight(guarded))

        guarded_completion = copy.deepcopy(self.completion_receipt)
        guarded_completion.update(returned_run_id=802)
        guarded_completion["preflight_sha256"] = guarded["preflight_sha256"]
        guarded_completion["completion_sha256"] = _canonical_sha256(
            {k: v for k, v in guarded_completion.items() if k != "completion_sha256"}
        )
        guarded_observation = copy.deepcopy(self.platform_observation)
        guarded_delivery = copy.deepcopy(self.dispatch_delivery_receipt)
        guarded_delivery.update(
            request_endpoint="/repos/octo/review-fixture/actions/workflows/901/dispatches",
            delivery_status="provider-returned-run-id",
            response_status=200,
            returned_run_id=802,
            unique_run_id=802,
        )
        guarded_delivery["request_body"] = {
            "ref": guarded_operation["ref"],
            "inputs": {
                item["name"]: item["value"] for item in guarded_operation["inputs"]
            },
        }
        guarded_delivery["request_body_sha256"] = _canonical_sha256(
            guarded_delivery["request_body"]
        )
        guarded_delivery["response"] = {
            "workflow_run_id": 802,
            "run_url": "https://api.github.com/repos/octo/review-fixture/actions/runs/802",
            "html_url": "https://github.com/octo/review-fixture/actions/runs/802",
        }
        guarded_delivery["response_sha256"] = _canonical_sha256(
            guarded_delivery["response"]
        )
        guarded_delivery["receipt_sha256"] = _receipt_sha256(guarded_delivery)
        guarded_observation["returned_run_id"] = 802
        guarded_observation["query_endpoint"] = (
            "/repos/octo/review-fixture/actions/runs/802"
        )
        guarded_observation["run_object"]["id"] = 802
        guarded_observation["run_object_sha256"] = _canonical_sha256(
            guarded_observation["run_object"]
        )
        guarded_observation["preflight_sha256"] = guarded["preflight_sha256"]
        guarded_observation["operation_identity_sha256"] = guarded["repeat_safety"][
            "operation_identity_sha256"
        ]
        guarded_observation["dispatch_delivery_receipt_sha256"] = guarded_delivery[
            "receipt_sha256"
        ]
        guarded_observation["receipt_sha256"] = _receipt_sha256(guarded_observation)
        guarded_validator = _RecoveryContractValidator(
            self.recovery_schema,
            self.producer_receipt,
            self.carriers["required_report_schema"]["parent_input_profiles"][
                "merge_status_producer_implementation_receipt"
            ],
            guarded_observation,
            guarded_delivery,
            guarded_delivery["receipt_sha256"],
        )
        self.assertTrue(
            guarded_validator.validate_completion(guarded_completion, guarded)
        )

        delivery_attacks = {
            "wrong-version": lambda receipt: receipt.update(api_version="2022-11-28"),
            "status-204": lambda receipt: receipt.update(response_status=204),
            "wrong-run-url": lambda receipt: receipt["response"].update(
                run_url="https://api.github.com/repos/octo/review-fixture/actions/runs/999"
            ),
            "wrong-html-url": lambda receipt: receipt["response"].update(
                html_url="https://github.com/octo/review-fixture/actions/runs/999"
            ),
            "extra-response-field": lambda receipt: receipt["response"].update(
                extra=True
            ),
            "response-id-drift": lambda receipt: receipt["response"].update(
                workflow_run_id=999
            ),
            "list-inputs-body": lambda receipt: receipt["request_body"].update(
                inputs=copy.deepcopy(guarded_operation["inputs"])
            ),
            "missing-ref": lambda receipt: receipt["request_body"].pop("ref"),
            "changed-ref": lambda receipt: receipt["request_body"].update(
                ref="refs/heads/other"
            ),
            "extra-wire-field": lambda receipt: receipt["request_body"].update(
                extra=True
            ),
        }
        for name, mutate in delivery_attacks.items():
            with self.subTest(delivery_attack=name):
                attacked_delivery = copy.deepcopy(guarded_delivery)
                mutate(attacked_delivery)
                attacked_delivery["request_body_sha256"] = _canonical_sha256(
                    attacked_delivery["request_body"]
                )
                attacked_delivery["response_sha256"] = _canonical_sha256(
                    attacked_delivery["response"]
                )
                attacked_delivery["receipt_sha256"] = _receipt_sha256(attacked_delivery)
                attacked_observation = copy.deepcopy(guarded_observation)
                attacked_observation["dispatch_delivery_receipt_sha256"] = (
                    attacked_delivery["receipt_sha256"]
                )
                attacked_observation["receipt_sha256"] = _receipt_sha256(
                    attacked_observation
                )
                attacked_validator = _RecoveryContractValidator(
                    self.recovery_schema,
                    self.producer_receipt,
                    self.carriers["required_report_schema"]["parent_input_profiles"][
                        "merge_status_producer_implementation_receipt"
                    ],
                    attacked_observation,
                    attacked_delivery,
                    guarded_delivery["receipt_sha256"],
                )
                self.assertFalse(
                    attacked_validator.validate_completion(guarded_completion, guarded)
                )

        duplicate_intent = copy.deepcopy(guarded)
        duplicate_intent["operation_intent"]["inputs"].append(
            copy.deepcopy(duplicate_intent["operation_intent"]["inputs"][0])
        )
        duplicate_intent["repeat_safety"]["operation_identity_sha256"] = (
            _canonical_sha256(duplicate_intent["operation_intent"])
        )
        duplicate_intent["preflight_sha256"] = _canonical_sha256(
            {
                key: value
                for key, value in duplicate_intent.items()
                if key != "preflight_sha256"
            }
        )
        self.assertFalse(guarded_validator.validate_preflight(duplicate_intent))

        arbitrary_returned_id = copy.deepcopy(guarded_completion)
        arbitrary_returned_id["returned_run_id"] = 999
        arbitrary_returned_id["completion_sha256"] = _canonical_sha256(
            {
                key: value
                for key, value in arbitrary_returned_id.items()
                if key != "completion_sha256"
            }
        )
        self.assertFalse(
            guarded_validator.validate_completion(arbitrary_returned_id, guarded)
        )

        swapped_observation = copy.deepcopy(guarded_observation)
        swapped_observation["returned_run_id"] = 999
        swapped_observation["query_endpoint"] = (
            "/repos/octo/review-fixture/actions/runs/999"
        )
        swapped_observation["run_object"]["id"] = 999
        swapped_observation["run_object_sha256"] = _canonical_sha256(
            swapped_observation["run_object"]
        )
        swapped_observation["receipt_sha256"] = _receipt_sha256(swapped_observation)
        swapped_completion = copy.deepcopy(guarded_completion)
        swapped_completion["returned_run_id"] = 999
        swapped_completion["completion_sha256"] = _canonical_sha256(
            {
                key: value
                for key, value in swapped_completion.items()
                if key != "completion_sha256"
            }
        )
        swapped_validator = _RecoveryContractValidator(
            self.recovery_schema,
            self.producer_receipt,
            self.carriers["required_report_schema"]["parent_input_profiles"][
                "merge_status_producer_implementation_receipt"
            ],
            swapped_observation,
            guarded_delivery,
            guarded_delivery["receipt_sha256"],
        )
        self.assertFalse(
            swapped_validator.validate_completion(swapped_completion, guarded)
        )

        coupled_delivery = copy.deepcopy(guarded_delivery)
        coupled_delivery.update(returned_run_id=999, unique_run_id=999)
        coupled_delivery["response"] = {
            "workflow_run_id": 999,
            "run_url": "https://api.github.com/repos/octo/review-fixture/actions/runs/999",
            "html_url": "https://github.com/octo/review-fixture/actions/runs/999",
        }
        coupled_delivery["response_sha256"] = _canonical_sha256(
            coupled_delivery["response"]
        )
        coupled_delivery["receipt_sha256"] = _receipt_sha256(coupled_delivery)
        coupled_observation = copy.deepcopy(swapped_observation)
        coupled_observation["dispatch_delivery_receipt_sha256"] = coupled_delivery[
            "receipt_sha256"
        ]
        coupled_observation["receipt_sha256"] = _receipt_sha256(coupled_observation)
        coupled_validator = _RecoveryContractValidator(
            self.recovery_schema,
            self.producer_receipt,
            self.carriers["required_report_schema"]["parent_input_profiles"][
                "merge_status_producer_implementation_receipt"
            ],
            coupled_observation,
            coupled_delivery,
            guarded_delivery["receipt_sha256"],
        )
        self.assertFalse(
            coupled_validator.validate_completion(swapped_completion, guarded)
        )

        arbitrary_existing_run = copy.deepcopy(self.recovery_contract)
        arbitrary_existing_run["operation_intent"].update(
            run_id=999, ref="refs/heads/forged"
        )
        arbitrary_existing_run["repeat_safety"]["operation_identity_sha256"] = (
            _canonical_sha256(arbitrary_existing_run["operation_intent"])
        )
        arbitrary_existing_run["preflight_sha256"] = _canonical_sha256(
            {k: v for k, v in arbitrary_existing_run.items() if k != "preflight_sha256"}
        )
        self.assertFalse(
            self.recovery_validator.validate_preflight(arbitrary_existing_run)
        )

        unbound_gate_entry = copy.deepcopy(guarded)
        unbound_gate_entry["operation_intent"]["expected_head_gate"][
            "implementation_entry_sha256"
        ] = "8" * 64
        unbound_gate_entry["repeat_safety"]["operation_identity_sha256"] = (
            _canonical_sha256(unbound_gate_entry["operation_intent"])
        )
        unbound_gate_entry["preflight_sha256"] = _canonical_sha256(
            {k: v for k, v in unbound_gate_entry.items() if k != "preflight_sha256"}
        )
        self.assertFalse(self.recovery_validator.validate_preflight(unbound_gate_entry))

        unresolved_candidate_dependency = copy.deepcopy(guarded)
        edge_receipt = unresolved_candidate_dependency[
            "dependency_edge_resolution_receipt"
        ]
        edge_receipt["resolved_edges"] = [
            {
                "caller_entry_sha256": "7" * 64,
                "reference": "./candidate-script.sh",
                "callee_entry_sha256": "8" * 64,
            }
        ]
        edge_receipt["resolved_edge_count"] = 1
        edge_receipt["resolved_edges_sha256"] = _canonical_sha256(
            edge_receipt["resolved_edges"]
        )
        edge_receipt["receipt_sha256"] = _receipt_sha256(edge_receipt)
        unresolved_candidate_dependency["preflight_sha256"] = _canonical_sha256(
            {
                k: v
                for k, v in unresolved_candidate_dependency.items()
                if k != "preflight_sha256"
            }
        )
        self.assertFalse(
            self.recovery_validator.validate_preflight(unresolved_candidate_dependency)
        )

        completion_ref_drift = copy.deepcopy(guarded_completion)
        completion_ref_drift["observed_run_ref"] = "refs/heads/other"
        completion_ref_drift["completion_sha256"] = _canonical_sha256(
            {k: v for k, v in completion_ref_drift.items() if k != "completion_sha256"}
        )
        self.assertFalse(
            guarded_validator.validate_completion(completion_ref_drift, guarded)
        )

        unsafe_dispatch = copy.deepcopy(guarded)
        unsafe_dispatch["operation_intent"]["expected_head_gate"] = copy.deepcopy(
            self.recovery_contract["operation_intent"]["expected_head_gate"]
        )
        unsafe_dispatch["repeat_safety"]["operation_identity_sha256"] = (
            _canonical_sha256(unsafe_dispatch["operation_intent"])
        )
        unsafe_dispatch["preflight_sha256"] = _canonical_sha256(
            {k: v for k, v in unsafe_dispatch.items() if k != "preflight_sha256"}
        )
        self.assertFalse(self.recovery_validator.validate_preflight(unsafe_dispatch))

        unbound_dispatch = copy.deepcopy(guarded_completion)
        unbound_dispatch["observed_workflow_sha"] = "9" * 40
        unbound_dispatch["completion_sha256"] = _canonical_sha256(
            {k: v for k, v in unbound_dispatch.items() if k != "completion_sha256"}
        )
        self.assertFalse(
            guarded_validator.validate_completion(unbound_dispatch, guarded)
        )

    def test_actions_repeat_requires_external_repeat_safety_contract_and_authorization(
        self,
    ) -> None:
        recovery = self.probes.split("## Reconcile Only Recoverable States", 1)[
            1
        ].split("## Retry Schedule And Cost Control", 1)[0]
        normalized = _normalize(recovery)

        self.assertIn(
            "obtain one closed parent-owned `recovery_operation_preflight`",
            normalized,
        )
        self.assertIn("anchored outside the candidate range", normalized)
        self.assertIn(
            "classifies that operation as idempotent or reentrant", normalized
        )
        self.assertIn(
            "equality identifies a requested repeat; it does not make an operation idempotent or reentrant",
            normalized,
        )
        self.assertIn("candidate-head workflow or contract bytes cannot", normalized)
        self.assertIn(
            "the current task must still authorize the external mutation", normalized
        )
        self.assertIn("keep the recovery owner in status-only mode", normalized)
        self.assertIn(
            "report the missing gate instead of triggering",
            normalized,
        )
        self.assertLess(
            normalized.index("obtain one closed parent-owned"),
            normalized.index("illustrative commands"),
        )
        combined = _normalize(
            self.skill
            + "\n"
            + self.probes
            + "\n"
            + self.authority
            + "\n"
            + self.contracts
            + "\n"
            + self.prompts
        )
        self.assertNotIn(
            "treats repetitions of that same tuple as idempotent", combined
        )
        self.assertNotIn("no repository-specific idempotency", combined)
        self.assertNotIn("same-head idempotent repository-action reconcile", combined)
        for anchor in (
            "single-flight",
            "workflow",
            "input set",
            "completion receipt",
            "ordinary confirmation",
            "never reconcile an explicit review finding",
        ):
            self.assertIn(anchor, combined)

    def test_merge_status_basis_binds_subject_scope_and_contract_clean(self) -> None:
        combined = _normalize(self.skill + "\n" + self.probes + "\n" + self.authority)
        for anchor in (
            "feature head",
            "current base",
            "unique merge base",
            "check_subject_sha",
            "github-synthetic-merge",
            "latest-feature-head",
            "current-merge-scope",
            "app/workflow/run/check",
            "does not require a separate terminal clean comment or review",
            "generic successful check",
            "service-start marker",
            "zero unresolved applicable",
            "type-preserving equality",
        ):
            self.assertIn(anchor, combined)

    def test_comment_creation_is_one_shot_across_github_contracts(
        self,
    ) -> None:
        authoritative_documents = {
            "probes": self.probes,
            "authority": self.authority,
        }
        routing_documents = {
            "lane-contracts": self.contracts,
            "prompt-templates": self.prompts,
        }
        authoritative_required = (
            "comment-mutation epoch",
            "at most one possibly delivered create-comment post",
            "complete visible exact-request set",
            "consumes the epoch's comment-mutation budget",
            "never repeat the comment post",
            "request_policy.status: unknown",
            "request-delivery-unproven",
            "audit warning",
            "same logical review lane",
            "never authorizes another comment write",
        )

        for name, document in authoritative_documents.items():
            normalized = _normalize(document)
            with self.subTest(document=name):
                for anchor in authoritative_required:
                    self.assertIn(anchor, normalized)

        routing_required = (
            "possibly delivered",
            "repository/pr/head epoch",
            "complete visible request set",
            "consumes the comment-mutation budget",
            "request_policy.status: unknown",
            "request-delivery-unproven",
            "never repeat the comment post in that epoch",
            "audit warning",
            "same logical",
            "never authorizes another",
        )
        for name, document in routing_documents.items():
            normalized = _normalize(document)
            with self.subTest(document=name):
                for anchor in routing_required:
                    self.assertIn(anchor, normalized)

        documents = authoritative_documents | routing_documents
        for name, document in documents.items():
            normalized = _normalize(document)
            with self.subTest(document=name):
                self.assertNotIn(
                    "the same exact `@codex review` post may be repeated", normalized
                )
                self.assertNotIn("idempotent delivery retry", normalized)
                self.assertNotIn("ambiguous-delivery recovery", normalized)

        combined = _normalize("\n".join(documents.values()))
        self.assertIn("only a new feature head creates a new", combined)
        self.assertIn(
            "only an independently authorized exact actions operation", combined
        )
        self.assertIn("never extends to comment creation", combined)
        self.assertNotIn("before every repetition", combined)

    def test_retry_schedule_cannot_repeat_comment_creation(self) -> None:
        request = self.probes.split("## Request The Review", 1)[1].split(
            "## Discover Related Checks Dynamically", 1
        )[0]
        recovery = self.probes.split("## Reconcile Only Recoverable States", 1)[
            1
        ].split("## Active Thread And Automation", 1)[0]
        failures = self.probes.split("## Probe Failures", 1)[1]
        normalized = _normalize(request + "\n" + recovery + "\n" + failures)

        for anchor in (
            "completely enumerate every page",
            "comment creation is not an idempotent operation",
            "it consumes the epoch's comment-mutation budget",
            "this repeat authority never applies to github comment creation",
            "the schedule never repeats a create-comment post",
            "generic transport retry rule applies to reads and eligible actions mutations only",
        ):
            self.assertIn(anchor, normalized)
        self.assertNotIn("idempotent delivery retry", normalized)

    def test_unbounded_backoff_is_limited_to_typed_retryable_reasons(self) -> None:
        retry = self.probes.split("## Retry Schedule And Cost Control", 1)[1].split(
            "## Active Thread And Automation", 1
        )[0]
        normalized = _normalize(retry)

        self.assertIn(
            "machine-decidable retryable pending or infrastructure reason",
            normalized,
        )
        self.assertIn("1, 2, 4, 8, 16, 32, 60, 60, 60", normalized)
        self.assertIn("no time ceiling on status-only monitoring", normalized)
        self.assertIn("mutation attempts stop at that cap", normalized)
        self.assertIn("github's total rerun limit is 50", _normalize(self.probes))
        self.assertIn("at 60 minutes, report", normalized)
        self.assertIn("then monitor hourly", normalized)
        self.assertIn("stable malformed snapshot", normalized)
        self.assertIn("non-retryable inconclusive state stops", normalized)

        combined = _normalize(self.skill + "\n" + self.probes + "\n" + self.authority)
        self.assertNotIn("inconclusive provider collection", combined)
        self.assertIn(
            "other non-retryable inconclusive state terminates recovery",
            combined,
        )

    def test_long_wait_uses_same_thread_and_private_throttling(self) -> None:
        automation = self.probes.split("## Active Thread And Automation", 1)[1]
        retry = self.probes.split("## Retry Schedule And Cost Control", 1)[1]
        normalized = _normalize(automation + "\n" + retry)

        for anchor in (
            "same active thread",
            "never create a new conversation",
            "pollable and cancellable active-thread fallback",
            "rolling budget of four full-run equivalents per 24 hours",
            "status-only hourly checks",
            "public repositories do not use the private-minute budget",
        ):
            self.assertIn(anchor, normalized)

    def test_only_applicable_unresolved_findings_block(self) -> None:
        findings = self.authority.split("## Finding Precedence And Resolution", 1)[
            1
        ].split("## Reaction-Only Fallback", 1)[0]
        normalized = _normalize(findings)

        self.assertIn("typed `isresolved == true`", normalized)
        self.assertIn(
            "removes the finding from `unresolved_provider_findings`", normalized
        )
        self.assertIn(
            "it does not require a replacement request or a new head", normalized
        )
        self.assertIn(
            "trustworthy provider clean correction on the same head", normalized
        )
        self.assertIn("generic correction prose is not enough", normalized)
        self.assertIn("if addressing the finding changes repository code", normalized)
        self.assertIn("commit that change as a new head", normalized)

        combined = _normalize(
            self.skill + "\n" + self.authority + "\n" + self.readiness
        )
        self.assertIn("only applicable unresolved provider findings block", combined)
        self.assertIn("requires fresh review", combined)
        self.assertIn(
            "a typed thread resolution or trustworthy same-head provider correction alone does not require a commit",
            combined,
        )
        self.assertNotIn(
            "provider findings block until fixed and resolved on a new reviewed head",
            combined,
        )

    def test_no_pr_uses_a_terminal_closed_null_scope_variant(self) -> None:
        report = self.authority.split("## Required Report", 1)[1]
        normalized = _normalize(report)
        scope_rule = self.carriers["required_report_schema"]["scope_rules"][
            "no-selected-supported-pr"
        ]

        self.assertIsNone(scope_rule["pull_request"])
        self.assertIsNone(scope_rule["head_sha"])
        self.assertEqual(scope_rule["status"], "not-applicable")
        for field, value in (
            ("status", scope_rule["status"]),
            ("pull_request", "null"),
            ("head_sha", "null"),
            ("scope_assurance", scope_rule["scope_assurance"]),
            ("base_assurance", scope_rule["base_assurance"]),
            ("basis", "null"),
            ("evidence", "null"),
            ("last_reason", scope_rule["last_reason"]),
        ):
            self.assertIn(f"{field}: {value}", report)
        self.assertIn("this no-pr variant is terminal", normalized)
        self.assertIn("it never enters retry recovery", normalized)
        self.assertIn("required null pr/head fields", normalized)


if __name__ == "__main__":
    unittest.main()
