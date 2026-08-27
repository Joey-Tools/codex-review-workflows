from __future__ import annotations

import copy
import datetime
import hashlib
import importlib
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


def _timestamp(value: object) -> datetime.datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


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
        expected_dependency_resolution_receipt: dict[str, object],
        expected_resolver_anchor: dict[str, object],
        expected_pre_mutation_observation: dict[str, object],
        post_current_observation: dict[str, object],
        acquisition_transaction_receipt: dict[str, object],
    ) -> None:
        self.schema = schema
        self.fields = schema["closed_fields"]
        self.producer_receipt = copy.deepcopy(producer_receipt)
        self.producer_receipt_fields = producer_receipt_fields
        self.platform_observation = copy.deepcopy(platform_observation)
        self.dispatch_delivery_receipt = copy.deepcopy(dispatch_delivery_receipt)
        self.expected_delivery_receipt_sha256 = expected_delivery_receipt_sha256
        self.expected_dependency_resolution_receipt = copy.deepcopy(
            expected_dependency_resolution_receipt
        )
        self.expected_resolver_anchor = copy.deepcopy(expected_resolver_anchor)
        self.expected_pre_mutation_observation = copy.deepcopy(
            expected_pre_mutation_observation
        )
        self.post_current_observation = copy.deepcopy(post_current_observation)
        self.acquisition_transaction_receipt = copy.deepcopy(
            acquisition_transaction_receipt
        )

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

    @staticmethod
    def _repository(value: object) -> bool:
        return (
            isinstance(value, str)
            and len(value.split("/")) == 2
            and all(value.split("/"))
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
        before = contract["pre_mutation_run_observation"]
        if (
            contract["owner"] != "parent-orchestrator"
            or contract["status"] != "complete"
            or contract["profile"] != "github-codex-recovery-operation-preflight-v1"
            or not self._repository(contract["repository"])
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
            or not self._closed(before, "pre_mutation_run_observation")
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
            "repository": producer["repository"],
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
            or producer["repository"] != contract["repository"]
            or not isinstance(producer["run_ref"], str)
            or not producer["run_ref"].startswith("refs/")
            or not self._positive_int(producer["run_id"])
            or not self._positive_int(producer["run_attempt"])
            or not self._positive_int(producer["check_suite_id"])
            or not self._positive_int(producer["check_run_id"])
            or not self._positive_int(producer["workflow_id"])
            or not isinstance(producer["implementation_closure"], list)
            or not producer["implementation_closure"]
            or not isinstance(producer["implementation_closure_count"], int)
            or isinstance(producer["implementation_closure_count"], bool)
            or producer["implementation_closure_count"]
            != len(producer["implementation_closure"])
            or producer["implementation_closure_sha256"]
            != _canonical_sha256(producer["implementation_closure"])
            or implementation != expected_implementation_identity
            or edges_receipt != self.expected_dependency_resolution_receipt
            or before != self.expected_pre_mutation_observation
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

        entries = producer["implementation_closure"]

        def entry_key(entry: dict[str, object]) -> tuple[object, ...]:
            return (
                entry["repository"],
                entry["commit"],
                entry["path"],
                entry["kind"],
                entry["blob_sha256"],
            )

        if any(
            not self._closed(entry, "implementation_entry")
            or not self._repository(entry["repository"])
            or not isinstance(entry["commit"], str)
            or FULL_SHA.fullmatch(entry["commit"]) is None
            or not self._safe_path(entry["path"])
            or not isinstance(entry["blob_sha256"], str)
            or SHA256.fullmatch(entry["blob_sha256"]) is None
            or entry["kind"]
            not in {"workflow", "reusable-workflow", "action", "script"}
            for entry in entries
        ):
            return False
        entry_by_key = {entry_key(item): item for item in entries}
        entry_keys = [entry_key(item) for item in entries]
        if entry_keys != sorted(entry_keys) or len(entry_keys) != len(set(entry_keys)):
            return False

        def ref_identity_matches(raw: object, identity: object) -> bool:
            if not self._closed(identity, "workflow_ref_identity"):
                return False
            entry = identity["entry"]
            return (
                self._closed(entry, "implementation_entry")
                and entry_key(entry) in entry_by_key
                and entry == entry_by_key[entry_key(entry)]
                and identity["entry_sha256"] == _canonical_sha256(entry)
                and identity["repository"] == entry["repository"]
                and identity["path"] == entry["path"]
                and identity["resolved_commit"] == entry["commit"]
                and isinstance(identity["ref"], str)
                and raw
                == f"{identity['repository']}/{identity['path']}@{identity['ref']}"
            )

        if (
            not self._repository(producer["workflow_repository"])
            or not self._safe_path(producer["workflow_path"])
            or FULL_SHA.fullmatch(producer["workflow_sha"]) is None
            or not ref_identity_matches(
                producer["workflow_ref"], producer["workflow_ref_identity"]
            )
            or not ref_identity_matches(
                producer["job_workflow_ref"], producer["job_workflow_ref_identity"]
            )
            or producer["workflow_ref_identity"]["repository"]
            != producer["workflow_repository"]
            or producer["workflow_ref_identity"]["path"] != producer["workflow_path"]
            or producer["workflow_ref_identity"]["resolved_commit"]
            != producer["workflow_sha"]
            or producer["workflow_ref_identity"]["ref"] != producer["run_ref"]
            or producer["external_implementation_id"] is not None
        ):
            return False

        workflow_entries = [
            item
            for item in producer["implementation_closure"]
            if item["kind"] == "workflow"
            and item["repository"] == producer["workflow_repository"]
            and item["commit"] == producer["workflow_sha"]
            and item["path"] == producer["workflow_path"]
        ]
        resolver = edges_receipt["resolver_anchor"]
        records = edges_receipt["records"]
        edges = edges_receipt["edges"]
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
            or not self._closed(resolver, "recovery_resolver_anchor")
            or resolver["owner"] != "parent-orchestrator"
            or resolver["status"] != "complete"
            or resolver["profile"] != "github-codex-recovery-resolver-anchor-v1"
            or resolver != self.expected_resolver_anchor
            or resolver["kind"]
            not in {
                "target-branch-baseline",
                "installed-trusted-release",
                "parent-fixed-external",
            }
            or FULL_SHA.fullmatch(resolver["commit"]) is None
            or not isinstance(resolver["repository"], str)
            or resolver["repository"].count("/") != 1
            or not self._safe_path(resolver["path"])
            or SHA256.fullmatch(resolver["sha256"]) is None
            or resolver["candidate_range_exclusion_sha256"]
            != _canonical_sha256(exclusion)
            or (
                resolver["kind"] == "target-branch-baseline"
                and (
                    resolver["repository"] != contract["repository"]
                    or resolver["commit"] != exclusion["base_sha"]
                    or resolver["installed_release_manifest_sha256"] is not None
                )
            )
            or (
                resolver["kind"] == "parent-fixed-external"
                and (
                    resolver["repository"] == contract["repository"]
                    or resolver["installed_release_manifest_sha256"] is not None
                )
            )
            or (
                resolver["kind"] == "installed-trusted-release"
                and SHA256.fullmatch(
                    resolver["installed_release_manifest_sha256"] or ""
                )
                is None
            )
            or (
                resolver["repository"] == contract["repository"]
                and resolver["commit"] in commits
            )
            or resolver["receipt_sha256"] != _receipt_sha256(resolver)
            or not isinstance(records, list)
            or edges_receipt["record_count"] != len(records)
            or edges_receipt["records_sha256"] != _canonical_sha256(records)
            or not isinstance(edges, list)
            or edges_receipt["edge_count"] != len(edges)
            or edges_receipt["edges_sha256"] != _canonical_sha256(edges)
            or edges_receipt["receipt_sha256"] != _receipt_sha256(edges_receipt)
            or any(
                item["repository"] == contract["repository"]
                and item["commit"] in commits
                for item in entries
            )
            or len(entry_by_key) != len(entries)
        ):
            return False

        derived_edges: list[dict[str, object]] = []
        record_keys: list[tuple[object, ...]] = []
        for record in records:
            if not self._closed(record, "recovery_resolution_record"):
                return False
            source_entry = record["source_entry"]
            references = record["discovered_references"]
            if (
                not isinstance(source_entry, dict)
                or entry_key(source_entry) not in entry_by_key
                or source_entry != entry_by_key[entry_key(source_entry)]
                or record["parser_profile"] != "github-actions-dependency-resolver-v1"
                or record["source_sha256"] != source_entry["blob_sha256"]
                or not isinstance(references, list)
                or references
                != sorted(
                    references,
                    key=lambda item: (
                        item.get("reference", "") if isinstance(item, dict) else "",
                        entry_key(item.get("target_entry", {}))
                        if isinstance(item, dict)
                        and isinstance(item.get("target_entry"), dict)
                        and set(item["target_entry"])
                        >= {"repository", "commit", "path", "kind", "blob_sha256"}
                        else (),
                    ),
                )
                or len(
                    {
                        (item["reference"], entry_key(item["target_entry"]))
                        for item in references
                        if isinstance(item, dict)
                        and "reference" in item
                        and isinstance(item.get("target_entry"), dict)
                    }
                )
                != len(references)
                or record["discovered_reference_count"] != len(references)
                or record["record_sha256"]
                != _canonical_sha256(
                    {k: v for k, v in record.items() if k != "record_sha256"}
                )
            ):
                return False
            record_keys.append(entry_key(source_entry))
            for reference in references:
                if not self._closed(reference, "recovery_dependency_reference"):
                    return False
                target = reference["target_entry"]
                if (
                    not isinstance(reference["reference"], str)
                    or not reference["reference"]
                    or not isinstance(target, dict)
                    or entry_key(target) not in entry_by_key
                    or target != entry_by_key[entry_key(target)]
                ):
                    return False
                derived_edges.append(
                    {
                        "source_entry": copy.deepcopy(source_entry),
                        "reference": reference["reference"],
                        "target_entry": copy.deepcopy(target),
                    }
                )
        derived_edges.sort(
            key=lambda edge: (
                *entry_key(edge["source_entry"]),
                edge["reference"],
                *entry_key(edge["target_entry"]),
            )
        )
        if (
            record_keys != sorted(entry_by_key)
            or len(record_keys) != len(set(record_keys))
            or edges != derived_edges
        ):
            return False

        inputs = operation["inputs"]
        if (
            operation["repository"] != contract["repository"]
            or operation["kind"]
            not in {
                "existing-run-rerun-failed-jobs",
                "existing-run-rerun-full",
                "guarded-dispatch",
            }
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
        if operation["kind"].startswith("existing-run-rerun-"):
            return (
                before["owner"] == "parent-orchestrator"
                and before["status"] == "complete"
                and before["profile"] == "github-codex-pre-mutation-run-observation-v1"
                and before["repository"] == contract["repository"]
                and before["query_endpoint"]
                == f"/repos/{contract['repository']}/actions/runs/{producer['run_id']}"
                and before["api_version"] == "2026-03-10"
                and before["http_method"] == "GET"
                and before["response_status"] == 200
                and _timestamp(before["response_date"]) is not None
                and before["run_id"] == producer["run_id"]
                and self._positive_int(before["run_id"])
                and before["run_attempt"] == producer["run_attempt"]
                and self._positive_int(before["run_attempt"])
                and operation["pre_run_attempt"] == before["run_attempt"]
                and operation["expected_run_attempt"] == before["run_attempt"] + 1
                and _timestamp(before["observed_at"]) is not None
                and before["head_sha"] == producer["feature_head_sha"]
                and before["workflow_id"] == producer["workflow_id"]
                and self._positive_int(before["workflow_id"])
                and before["workflow_sha"] == producer["workflow_sha"]
                and before["workflow_ref"] == producer["workflow_ref"]
                and before["run_ref"] == producer["run_ref"]
                and before["job_workflow_ref"] == producer["job_workflow_ref"]
                and self._closed(before["platform_identity"], "platform_identity")
                and before["platform_identity"]
                == {"source": "github-actions-api", "authenticated": True}
                and before["receipt_sha256"] == _receipt_sha256(before)
                and operation["run_id"] == producer["run_id"]
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
            and operation["pre_run_attempt"] is None
            and operation["expected_run_attempt"] is None
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
                "implementation_entry_sha256": _canonical_sha256(workflow_entries[0]),
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
        current_observation = self.post_current_observation
        transaction = self.acquisition_transaction_receipt
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
            or not isinstance(delivery["request_server_time"], str)
            or not delivery["request_server_time"]
            or delivery["delivery_status"]
            not in {
                "provider-returned-run-id",
                "existing-run-rerun-failed-jobs",
                "existing-run-rerun-full",
            }
            or not self._positive_int(delivery["returned_run_id"])
            or not self._positive_int(delivery["unique_run_id"])
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
            or observation["api_version"] != "2026-03-10"
            or observation["http_method"] != "GET"
            or observation["response_status"] != 200
            or _timestamp(observation["response_date"]) is None
            or observation["preflight_sha256"] != accepted_preflight["preflight_sha256"]
            or observation["operation_identity_sha256"]
            != accepted_preflight["repeat_safety"]["operation_identity_sha256"]
            or observation["dispatch_delivery_receipt_sha256"]
            != delivery["receipt_sha256"]
            or observation["request_delivery_status"] != "proved-delivered"
            or not self._positive_int(observation["returned_run_id"])
            or observation["returned_run_id"] != delivery["returned_run_id"]
            or not self._closed(run_object, "platform_dispatch_run_object")
            or not self._positive_int(run_object["id"])
            or not self._positive_int(run_object["run_attempt"])
            or not self._positive_int(run_object["workflow_id"])
            or run_object["id"] != observation["returned_run_id"]
            or observation["run_object_sha256"] != _canonical_sha256(run_object)
            or not self._closed(observation["platform_identity"], "platform_identity")
            or observation["platform_identity"]
            != {"source": "github-actions-api", "authenticated": True}
            or observation["receipt_sha256"] != _receipt_sha256(observation)
        ):
            return False
        current_run_object = (
            current_observation.get("run_object")
            if isinstance(current_observation, dict)
            else None
        )
        if (
            not self._closed(
                current_observation, "platform_dispatch_run_observation_receipt"
            )
            or current_observation["owner"] != "parent-orchestrator"
            or current_observation["status"] != "complete"
            or current_observation["profile"]
            != "github-codex-platform-dispatch-run-observation-v1"
            or current_observation["query_repository"]
            != accepted_preflight["repository"]
            or current_observation["query_endpoint"]
            != f"/repos/{accepted_preflight['repository']}/actions/runs/{observation['returned_run_id']}"
            or current_observation["api_version"] != "2026-03-10"
            or current_observation["http_method"] != "GET"
            or current_observation["response_status"] != 200
            or _timestamp(current_observation["response_date"]) is None
            or current_observation["preflight_sha256"]
            != accepted_preflight["preflight_sha256"]
            or current_observation["operation_identity_sha256"]
            != accepted_preflight["repeat_safety"]["operation_identity_sha256"]
            or current_observation["dispatch_delivery_receipt_sha256"]
            != delivery["receipt_sha256"]
            or current_observation["request_delivery_status"] != "proved-delivered"
            or not self._positive_int(current_observation["returned_run_id"])
            or current_observation["returned_run_id"] != observation["returned_run_id"]
            or not self._closed(current_run_object, "platform_dispatch_run_object")
            or not self._positive_int(current_run_object["id"])
            or not self._positive_int(current_run_object["run_attempt"])
            or not self._positive_int(current_run_object["workflow_id"])
            or current_run_object["id"] != observation["returned_run_id"]
            or current_observation["run_object_sha256"]
            != _canonical_sha256(current_run_object)
            or current_observation["platform_identity"]
            != {"source": "github-actions-api", "authenticated": True}
            or current_observation["receipt_sha256"]
            != _receipt_sha256(current_observation)
        ):
            return False
        frozen_identity_fields = (
            "id",
            "repository",
            "run_attempt",
            "previous_attempt_url",
            "head_sha",
            "workflow_id",
            "workflow_sha",
            "workflow_ref",
            "run_ref",
            "job_workflow_ref",
        )
        exact_started = _timestamp(run_object["run_started_at"])
        exact_updated = _timestamp(run_object["updated_at"])
        exact_response = _timestamp(observation["response_date"])
        exact_acquired = _timestamp(run_object["observed_at"])
        current_started = _timestamp(current_run_object["run_started_at"])
        current_updated = _timestamp(current_run_object["updated_at"])
        current_response = _timestamp(current_observation["response_date"])
        current_acquired = _timestamp(current_run_object["observed_at"])
        post_boundary = _timestamp(delivery["request_server_time"])
        before_response = _timestamp(
            accepted_preflight["pre_mutation_run_observation"]["response_date"]
        )
        before_acquired = _timestamp(
            accepted_preflight["pre_mutation_run_observation"]["observed_at"]
        )
        if (
            {key: current_run_object[key] for key in frozen_identity_fields}
            != {key: run_object[key] for key in frozen_identity_fields}
            or None
            in {
                exact_started,
                exact_updated,
                exact_response,
                exact_acquired,
                current_started,
                current_updated,
                current_response,
                current_acquired,
                post_boundary,
                before_response,
                before_acquired,
            }
            or exact_started != current_started
            or not (
                before_response
                <= before_acquired
                <= post_boundary
                <= exact_started
                <= exact_updated
                <= exact_response
                <= exact_acquired
                <= current_response
                <= current_acquired
            )
            or not (current_started <= current_updated <= current_response)
            or not self._closed(transaction, "recovery_acquisition_transaction_receipt")
            or transaction["owner"] != "parent-orchestrator"
            or transaction["status"] != "complete"
            or transaction["profile"]
            != "github-codex-recovery-acquisition-transaction-v1"
            or transaction["repository"] != accepted_preflight["repository"]
            or not self._positive_int(transaction["run_id"])
            or transaction["run_id"] != observation["returned_run_id"]
            or transaction["pre_observation_sha256"]
            != accepted_preflight["pre_mutation_run_observation"]["receipt_sha256"]
            or transaction["delivery_receipt_sha256"] != delivery["receipt_sha256"]
            or transaction["exact_attempt_observation_sha256"]
            != observation["receipt_sha256"]
            or transaction["current_run_observation_sha256"]
            != current_observation["receipt_sha256"]
            or transaction["pre_response_date"]
            != accepted_preflight["pre_mutation_run_observation"]["response_date"]
            or transaction["pre_acquired_at"]
            != accepted_preflight["pre_mutation_run_observation"]["observed_at"]
            or transaction["post_server_time"] != delivery["request_server_time"]
            or transaction["exact_response_date"] != observation["response_date"]
            or transaction["exact_acquired_at"] != run_object["observed_at"]
            or transaction["current_response_date"]
            != current_observation["response_date"]
            or transaction["current_acquired_at"] != current_run_object["observed_at"]
            or transaction["no_intervening_rerun"] is not True
            or transaction["receipt_sha256"] != _receipt_sha256(transaction)
        ):
            return False
        if operation["kind"].startswith("existing-run-rerun-"):
            expected_run_id = operation["run_id"]
            rerun_mode = operation["kind"].removeprefix("existing-run-rerun-")
            endpoint_suffix = (
                "rerun-failed-jobs" if rerun_mode == "failed-jobs" else "rerun"
            )
            producer_attempt = producer["run_attempt"]
            observed_at = _timestamp(run_object["observed_at"])
            requested_at = _timestamp(delivery["request_server_time"])
            before_at = _timestamp(
                accepted_preflight["pre_mutation_run_observation"]["observed_at"]
            )
            if (
                rerun_mode not in {"failed-jobs", "full"}
                or delivery["delivery_status"] != operation["kind"]
                or delivery["request_endpoint"]
                != f"/repos/{accepted_preflight['repository']}/actions/runs/{expected_run_id}/{endpoint_suffix}"
                or delivery["request_body"] is not None
                or delivery["request_body_encoding"] != "absent-v1"
                or delivery["request_body_sha256"] != _canonical_sha256(None)
                or delivery["response_status"] != 201
                or delivery["response"] is not None
                or delivery["response_sha256"] is not None
                or not self._positive_int(producer_attempt)
                or not self._positive_int(run_object["run_attempt"])
                or run_object["run_attempt"] != producer_attempt + 1
                or run_object["run_attempt"] != operation["expected_run_attempt"]
                or observation["query_endpoint"]
                != f"/repos/{accepted_preflight['repository']}/actions/runs/{expected_run_id}/attempts/{producer_attempt + 1}"
                or before_at is None
                or requested_at is None
                or observed_at is None
                or requested_at < before_at
                or observed_at < requested_at
                or _timestamp(observation["response_date"]) < requested_at
                or observed_at < _timestamp(observation["response_date"])
                or _timestamp(run_object["run_started_at"]) is None
                or _timestamp(run_object["updated_at"]) is None
                or not (
                    requested_at
                    <= _timestamp(run_object["run_started_at"])
                    <= _timestamp(run_object["updated_at"])
                    <= _timestamp(observation["response_date"])
                    <= observed_at
                )
                or _timestamp(current_run_object["run_started_at"])
                != _timestamp(run_object["run_started_at"])
                or _timestamp(current_run_object["updated_at"])
                < _timestamp(current_run_object["run_started_at"])
                or _timestamp(current_run_object["updated_at"])
                > _timestamp(current_observation["response_date"])
                or run_object["previous_attempt_url"]
                != f"https://api.github.com/repos/{accepted_preflight['repository']}/actions/runs/{expected_run_id}/attempts/{producer_attempt}"
                or current_run_object["run_attempt"] != producer_attempt + 1
                or current_run_object["previous_attempt_url"]
                != run_object["previous_attempt_url"]
                or {
                    key: current_run_object[key]
                    for key in (
                        "id",
                        "repository",
                        "run_attempt",
                        "previous_attempt_url",
                        "head_sha",
                        "workflow_id",
                        "workflow_sha",
                        "workflow_ref",
                        "run_ref",
                        "job_workflow_ref",
                    )
                }
                != {
                    key: run_object[key]
                    for key in (
                        "id",
                        "repository",
                        "run_attempt",
                        "previous_attempt_url",
                        "head_sha",
                        "workflow_id",
                        "workflow_sha",
                        "workflow_ref",
                        "run_ref",
                        "job_workflow_ref",
                    )
                }
                or not self._closed(
                    transaction, "recovery_acquisition_transaction_receipt"
                )
                or transaction["owner"] != "parent-orchestrator"
                or transaction["status"] != "complete"
                or transaction["profile"]
                != "github-codex-recovery-acquisition-transaction-v1"
                or transaction["repository"] != accepted_preflight["repository"]
                or transaction["run_id"] != expected_run_id
                or transaction["pre_observation_sha256"]
                != accepted_preflight["pre_mutation_run_observation"]["receipt_sha256"]
                or transaction["delivery_receipt_sha256"] != delivery["receipt_sha256"]
                or transaction["exact_attempt_observation_sha256"]
                != observation["receipt_sha256"]
                or transaction["current_run_observation_sha256"]
                != current_observation["receipt_sha256"]
                or transaction["pre_response_date"]
                != accepted_preflight["pre_mutation_run_observation"]["response_date"]
                or transaction["pre_acquired_at"]
                != accepted_preflight["pre_mutation_run_observation"]["observed_at"]
                or transaction["post_server_time"] != delivery["request_server_time"]
                or transaction["exact_response_date"] != observation["response_date"]
                or transaction["exact_acquired_at"] != run_object["observed_at"]
                or transaction["current_response_date"]
                != current_observation["response_date"]
                or transaction["current_acquired_at"]
                != current_run_object["observed_at"]
                or transaction["no_intervening_rerun"] is not True
                or transaction["receipt_sha256"] != _receipt_sha256(transaction)
                or not (
                    _timestamp(transaction["pre_response_date"])
                    <= _timestamp(transaction["pre_acquired_at"])
                    <= _timestamp(transaction["post_server_time"])
                    <= _timestamp(transaction["exact_response_date"])
                    <= _timestamp(transaction["exact_acquired_at"])
                    <= _timestamp(transaction["current_response_date"])
                    <= _timestamp(transaction["current_acquired_at"])
                )
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
                or observation["query_endpoint"]
                != f"/repos/{accepted_preflight['repository']}/actions/runs/{observation['returned_run_id']}"
                or delivery["request_body_encoding"] != "rfc8785-semantic-json-v1"
                or delivery["request_body_sha256"]
                != _canonical_sha256(delivery["request_body"])
                or delivery["request_endpoint"]
                != f"/repos/{accepted_preflight['repository']}/actions/workflows/{operation['workflow_id']}/dispatches"
                or not operation["inputs"]
                or not self._closed(delivery["request_body"], "dispatch_request_body")
                or delivery["request_body"] != semantic_body
                or delivery["response_status"] != 200
                or not self._closed(response, "dispatch_response")
                or not self._positive_int(response["workflow_run_id"])
                or response["workflow_run_id"] != delivery["returned_run_id"]
                or response["workflow_run_id"] != delivery["unique_run_id"]
                or response["workflow_run_id"] != observation["returned_run_id"]
                or response["run_url"]
                != f"https://api.github.com/repos/{accepted_preflight['repository']}/actions/runs/{response['workflow_run_id']}"
                or response["html_url"]
                != f"https://github.com/{accepted_preflight['repository']}/actions/runs/{response['workflow_run_id']}"
                or delivery["response_sha256"] != _canonical_sha256(response)
                or not self._positive_int(run_object["run_attempt"])
                or run_object["run_attempt"] != 1
                or run_object["previous_attempt_url"] is not None
                or _timestamp(run_object["observed_at"]) is None
                or _timestamp(delivery["request_server_time"]) is None
                or _timestamp(run_object["observed_at"])
                < _timestamp(delivery["request_server_time"])
            ):
                return False
        return (
            completion["owner"] == "parent-orchestrator"
            and completion["status"] == "complete"
            and completion["profile"] == "github-codex-recovery-operation-completion-v1"
            and completion["preflight_sha256"] == accepted_preflight["preflight_sha256"]
            and completion["pre_mutation_observation_sha256"]
            == accepted_preflight["pre_mutation_run_observation"]["receipt_sha256"]
            and completion["dispatch_delivery_receipt_sha256"]
            == delivery["receipt_sha256"]
            and completion["platform_observation_receipt_sha256"]
            == observation["receipt_sha256"]
            and completion["post_current_observation_receipt_sha256"]
            == current_observation["receipt_sha256"]
            and completion["acquisition_transaction_receipt_sha256"]
            == transaction["receipt_sha256"]
            and self._positive_int(completion["returned_run_id"])
            and completion["returned_run_id"] == expected_run_id
            and completion["returned_run_id"] == observation["returned_run_id"]
            and completion["observed_repository"]
            == run_object["repository"]
            == accepted_preflight["repository"]
            and self._positive_int(completion["observed_run_attempt"])
            and completion["observed_run_attempt"] == run_object["run_attempt"]
            and completion["observed_head_sha"]
            == run_object["head_sha"]
            == accepted_preflight["head_sha"]
            and self._positive_int(completion["observed_workflow_id"])
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
            },
            {
                "repository": "octo/recovery-policy",
                "commit": "2" * 40,
                "path": "actions/reconcile/action.yml",
                "blob_sha256": "8" * 64,
                "kind": "action",
            },
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
            "implementation_closure_count": len(producer_closure),
            "implementation_closure_sha256": _canonical_sha256(producer_closure),
            "receipt_sha256": "",
        }
        cls.producer_receipt["receipt_sha256"] = _receipt_sha256(cls.producer_receipt)
        cls.implementation_identity = {
            "profile": cls.producer_receipt["profile"],
            "receipt_sha256": cls.producer_receipt["receipt_sha256"],
            "provider_kind": cls.producer_receipt["provider_kind"],
            "repository": cls.producer_receipt["repository"],
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
            "repository": "octo/review-fixture",
            "kind": "existing-run-rerun-full",
            "workflow_id": 901,
            "run_id": 801,
            "pre_run_attempt": 1,
            "expected_run_attempt": 2,
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
        exclusion_receipt = {
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
        }
        resolver_anchor = {
            "owner": "parent-orchestrator",
            "status": "complete",
            "profile": "github-codex-recovery-resolver-anchor-v1",
            "kind": "parent-fixed-external",
            "repository": "octo/recovery-policy",
            "commit": "3" * 40,
            "path": "resolvers/github-actions-dependencies.py",
            "sha256": "6" * 64,
            "candidate_range_exclusion_sha256": _canonical_sha256(exclusion_receipt),
            "installed_release_manifest_sha256": None,
            "receipt_sha256": "",
        }
        resolver_anchor["receipt_sha256"] = _receipt_sha256(resolver_anchor)
        resolution_record = {
            "source_entry": copy.deepcopy(producer_closure[0]),
            "parser_profile": "github-actions-dependency-resolver-v1",
            "source_sha256": producer_closure[0]["blob_sha256"],
            "discovered_references": [
                {
                    "reference": "./actions/reconcile",
                    "target_entry": copy.deepcopy(producer_closure[1]),
                }
            ],
            "discovered_reference_count": 1,
            "record_sha256": "",
        }
        resolution_record["record_sha256"] = _canonical_sha256(
            {k: v for k, v in resolution_record.items() if k != "record_sha256"}
        )
        action_record = {
            "source_entry": copy.deepcopy(producer_closure[1]),
            "parser_profile": "github-actions-dependency-resolver-v1",
            "source_sha256": producer_closure[1]["blob_sha256"],
            "discovered_references": [],
            "discovered_reference_count": 0,
            "record_sha256": "",
        }
        action_record["record_sha256"] = _canonical_sha256(
            {k: v for k, v in action_record.items() if k != "record_sha256"}
        )
        resolution_records = sorted(
            [resolution_record, action_record],
            key=lambda record: (
                record["source_entry"]["repository"],
                record["source_entry"]["commit"],
                record["source_entry"]["path"],
                record["source_entry"]["kind"],
                record["source_entry"]["blob_sha256"],
            ),
        )
        resolution_edges = [
            {
                "source_entry": copy.deepcopy(producer_closure[0]),
                "reference": "./actions/reconcile",
                "target_entry": copy.deepcopy(producer_closure[1]),
            }
        ]
        edge_receipt = {
            "owner": "parent-orchestrator",
            "status": "complete",
            "profile": "github-codex-recovery-dependency-edge-resolution-v1",
            "implementation_receipt_sha256": cls.producer_receipt["receipt_sha256"],
            "repository": "octo/review-fixture",
            "head_sha": head_sha,
            "resolver_anchor": resolver_anchor,
            "records": resolution_records,
            "record_count": 2,
            "records_sha256": _canonical_sha256(resolution_records),
            "edges": resolution_edges,
            "edge_count": 1,
            "edges_sha256": _canonical_sha256(resolution_edges),
            "receipt_sha256": "",
        }
        edge_receipt["receipt_sha256"] = _receipt_sha256(edge_receipt)
        pre_mutation_observation = {
            "owner": "parent-orchestrator",
            "status": "complete",
            "profile": "github-codex-pre-mutation-run-observation-v1",
            "repository": "octo/review-fixture",
            "query_endpoint": "/repos/octo/review-fixture/actions/runs/801",
            "api_version": "2026-03-10",
            "http_method": "GET",
            "response_status": 200,
            "response_date": "2026-08-26T09:59:00Z",
            "run_id": 801,
            "run_attempt": 1,
            "observed_at": "2026-08-26T09:59:00Z",
            "head_sha": head_sha,
            "workflow_id": 901,
            "workflow_sha": "2" * 40,
            "workflow_ref": cls.producer_receipt["workflow_ref"],
            "run_ref": "refs/heads/feature/review",
            "job_workflow_ref": cls.producer_receipt["job_workflow_ref"],
            "platform_identity": {
                "source": "github-actions-api",
                "authenticated": True,
            },
            "receipt_sha256": "",
        }
        pre_mutation_observation["receipt_sha256"] = _receipt_sha256(
            pre_mutation_observation
        )
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
            "candidate_range_exclusion_receipt": exclusion_receipt,
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
            "pre_mutation_run_observation": pre_mutation_observation,
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
            "pre_mutation_observation_sha256": pre_mutation_observation[
                "receipt_sha256"
            ],
            "dispatch_delivery_receipt_sha256": "",
            "platform_observation_receipt_sha256": "",
            "post_current_observation_receipt_sha256": "",
            "acquisition_transaction_receipt_sha256": "",
            "returned_run_id": 801,
            "observed_repository": "octo/review-fixture",
            "observed_run_attempt": 2,
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
            "run_attempt": 2,
            "observed_at": "2026-08-26T10:01:00Z",
            "run_started_at": "2026-08-26T10:00:30Z",
            "updated_at": "2026-08-26T10:00:45Z",
            "previous_attempt_url": "https://api.github.com/repos/octo/review-fixture/actions/runs/801/attempts/1",
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
            "request_body": None,
            "request_body_encoding": "absent-v1",
            "request_body_sha256": _canonical_sha256(None),
            "request_server_time": "2026-08-26T10:00:00Z",
            "delivery_status": "existing-run-rerun-full",
            "response_status": 201,
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
            "query_endpoint": "/repos/octo/review-fixture/actions/runs/801/attempts/2",
            "api_version": "2026-03-10",
            "http_method": "GET",
            "response_status": 200,
            "response_date": "2026-08-26T10:01:00Z",
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
        cls.post_current_observation = copy.deepcopy(cls.platform_observation)
        cls.post_current_observation["query_endpoint"] = (
            "/repos/octo/review-fixture/actions/runs/801"
        )
        cls.post_current_observation["response_date"] = "2026-08-26T10:01:01Z"
        cls.post_current_observation["run_object"]["observed_at"] = (
            "2026-08-26T10:01:01Z"
        )
        cls.post_current_observation["run_object_sha256"] = _canonical_sha256(
            cls.post_current_observation["run_object"]
        )
        cls.post_current_observation["receipt_sha256"] = _receipt_sha256(
            cls.post_current_observation
        )
        cls.acquisition_transaction = {
            "owner": "parent-orchestrator",
            "status": "complete",
            "profile": "github-codex-recovery-acquisition-transaction-v1",
            "repository": "octo/review-fixture",
            "run_id": 801,
            "pre_observation_sha256": pre_mutation_observation["receipt_sha256"],
            "delivery_receipt_sha256": cls.dispatch_delivery_receipt["receipt_sha256"],
            "exact_attempt_observation_sha256": cls.platform_observation[
                "receipt_sha256"
            ],
            "current_run_observation_sha256": cls.post_current_observation[
                "receipt_sha256"
            ],
            "pre_response_date": pre_mutation_observation["response_date"],
            "pre_acquired_at": pre_mutation_observation["observed_at"],
            "post_server_time": cls.dispatch_delivery_receipt["request_server_time"],
            "exact_response_date": cls.platform_observation["response_date"],
            "exact_acquired_at": cls.platform_observation["run_object"]["observed_at"],
            "current_response_date": cls.post_current_observation["response_date"],
            "current_acquired_at": cls.post_current_observation["run_object"][
                "observed_at"
            ],
            "no_intervening_rerun": True,
            "receipt_sha256": "",
        }
        cls.acquisition_transaction["receipt_sha256"] = _receipt_sha256(
            cls.acquisition_transaction
        )
        cls.completion_receipt["dispatch_delivery_receipt_sha256"] = (
            cls.dispatch_delivery_receipt["receipt_sha256"]
        )
        cls.completion_receipt["platform_observation_receipt_sha256"] = (
            cls.platform_observation["receipt_sha256"]
        )
        cls.completion_receipt["post_current_observation_receipt_sha256"] = (
            cls.post_current_observation["receipt_sha256"]
        )
        cls.completion_receipt["acquisition_transaction_receipt_sha256"] = (
            cls.acquisition_transaction["receipt_sha256"]
        )
        cls.completion_receipt["completion_sha256"] = _canonical_sha256(
            {
                key: value
                for key, value in cls.completion_receipt.items()
                if key != "completion_sha256"
            }
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
            cls.recovery_contract["dependency_edge_resolution_receipt"],
            cls.recovery_contract["dependency_edge_resolution_receipt"][
                "resolver_anchor"
            ],
            cls.recovery_contract["pre_mutation_run_observation"],
            cls.post_current_observation,
            cls.acquisition_transaction,
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
            pre_run_attempt=None,
            expected_run_attempt=None,
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
                "implementation_entry_sha256": _canonical_sha256(
                    self.producer_receipt["implementation_closure"][0]
                ),
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
        guarded_completion.update(returned_run_id=802, observed_run_attempt=1)
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
        guarded_delivery["request_body_encoding"] = "rfc8785-semantic-json-v1"
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
        guarded_observation["run_object"]["run_attempt"] = 1
        guarded_observation["run_object"]["previous_attempt_url"] = None
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
        guarded_current_observation = copy.deepcopy(guarded_observation)
        guarded_current_observation["receipt_sha256"] = _receipt_sha256(
            guarded_current_observation
        )
        guarded_transaction = copy.deepcopy(self.acquisition_transaction)
        guarded_transaction.update(
            run_id=802,
            pre_observation_sha256=guarded["pre_mutation_run_observation"][
                "receipt_sha256"
            ],
            delivery_receipt_sha256=guarded_delivery["receipt_sha256"],
            exact_attempt_observation_sha256=guarded_observation["receipt_sha256"],
            current_run_observation_sha256=guarded_current_observation[
                "receipt_sha256"
            ],
            exact_response_date=guarded_observation["response_date"],
            exact_acquired_at=guarded_observation["run_object"]["observed_at"],
            current_response_date=guarded_current_observation["response_date"],
            current_acquired_at=guarded_current_observation["run_object"][
                "observed_at"
            ],
        )
        guarded_transaction["receipt_sha256"] = _receipt_sha256(guarded_transaction)
        guarded_completion["pre_mutation_observation_sha256"] = guarded[
            "pre_mutation_run_observation"
        ]["receipt_sha256"]
        guarded_completion["dispatch_delivery_receipt_sha256"] = guarded_delivery[
            "receipt_sha256"
        ]
        guarded_completion["platform_observation_receipt_sha256"] = guarded_observation[
            "receipt_sha256"
        ]
        guarded_completion["post_current_observation_receipt_sha256"] = (
            guarded_current_observation["receipt_sha256"]
        )
        guarded_completion["acquisition_transaction_receipt_sha256"] = (
            guarded_transaction["receipt_sha256"]
        )
        guarded_completion["completion_sha256"] = _canonical_sha256(
            {k: v for k, v in guarded_completion.items() if k != "completion_sha256"}
        )
        guarded_validator = _RecoveryContractValidator(
            self.recovery_schema,
            self.producer_receipt,
            self.carriers["required_report_schema"]["parent_input_profiles"][
                "merge_status_producer_implementation_receipt"
            ],
            guarded_observation,
            guarded_delivery,
            guarded_delivery["receipt_sha256"],
            guarded["dependency_edge_resolution_receipt"],
            guarded["dependency_edge_resolution_receipt"]["resolver_anchor"],
            guarded["pre_mutation_run_observation"],
            guarded_current_observation,
            guarded_transaction,
        )
        self.assertTrue(
            guarded_validator.validate_completion(guarded_completion, guarded)
        )

        id_one_delivery = copy.deepcopy(guarded_delivery)
        id_one_delivery.update(returned_run_id=1, unique_run_id=1)
        id_one_delivery["response"] = {
            "workflow_run_id": 1,
            "run_url": "https://api.github.com/repos/octo/review-fixture/actions/runs/1",
            "html_url": "https://github.com/octo/review-fixture/actions/runs/1",
        }
        id_one_delivery["response_sha256"] = _canonical_sha256(
            id_one_delivery["response"]
        )
        id_one_delivery["receipt_sha256"] = _receipt_sha256(id_one_delivery)
        id_one_observation = copy.deepcopy(guarded_observation)
        id_one_observation.update(
            returned_run_id=1,
            query_endpoint="/repos/octo/review-fixture/actions/runs/1",
            dispatch_delivery_receipt_sha256=id_one_delivery["receipt_sha256"],
        )
        id_one_observation["run_object"]["id"] = 1
        id_one_observation["run_object_sha256"] = _canonical_sha256(
            id_one_observation["run_object"]
        )
        id_one_observation["receipt_sha256"] = _receipt_sha256(id_one_observation)
        id_one_current = copy.deepcopy(guarded_current_observation)
        id_one_current.update(
            returned_run_id=1,
            query_endpoint="/repos/octo/review-fixture/actions/runs/1",
            dispatch_delivery_receipt_sha256=id_one_delivery["receipt_sha256"],
        )
        id_one_current["run_object"]["id"] = 1
        id_one_current["run_object_sha256"] = _canonical_sha256(
            id_one_current["run_object"]
        )
        id_one_current["receipt_sha256"] = _receipt_sha256(id_one_current)
        id_one_transaction = copy.deepcopy(guarded_transaction)
        id_one_transaction.update(
            run_id=1,
            delivery_receipt_sha256=id_one_delivery["receipt_sha256"],
            exact_attempt_observation_sha256=id_one_observation["receipt_sha256"],
            current_run_observation_sha256=id_one_current["receipt_sha256"],
        )
        id_one_transaction["receipt_sha256"] = _receipt_sha256(id_one_transaction)
        id_one_completion = copy.deepcopy(guarded_completion)
        id_one_completion.update(
            returned_run_id=1,
            dispatch_delivery_receipt_sha256=id_one_delivery["receipt_sha256"],
            platform_observation_receipt_sha256=id_one_observation["receipt_sha256"],
            post_current_observation_receipt_sha256=id_one_current["receipt_sha256"],
            acquisition_transaction_receipt_sha256=id_one_transaction["receipt_sha256"],
        )
        id_one_completion["completion_sha256"] = _canonical_sha256(
            {k: v for k, v in id_one_completion.items() if k != "completion_sha256"}
        )

        def id_one_validator(
            current: dict[str, object], transaction: dict[str, object]
        ) -> _RecoveryContractValidator:
            return _RecoveryContractValidator(
                self.recovery_schema,
                self.producer_receipt,
                self.carriers["required_report_schema"]["parent_input_profiles"][
                    "merge_status_producer_implementation_receipt"
                ],
                id_one_observation,
                id_one_delivery,
                id_one_delivery["receipt_sha256"],
                guarded["dependency_edge_resolution_receipt"],
                guarded["dependency_edge_resolution_receipt"]["resolver_anchor"],
                guarded["pre_mutation_run_observation"],
                current,
                transaction,
            )

        self.assertTrue(
            id_one_validator(id_one_current, id_one_transaction).validate_completion(
                id_one_completion, guarded
            )
        )
        for typed_id in (True, 1.0):
            with self.subTest(shared_run_id_type=type(typed_id).__name__):
                typed_current_id = copy.deepcopy(id_one_current)
                typed_observation_id = copy.deepcopy(id_one_observation)
                for receipt in (typed_observation_id, typed_current_id):
                    receipt["run_object"]["id"] = typed_id
                    receipt["run_object_sha256"] = _canonical_sha256(
                        receipt["run_object"]
                    )
                    receipt["receipt_sha256"] = _receipt_sha256(receipt)
                typed_id_transaction = copy.deepcopy(id_one_transaction)
                typed_id_transaction["exact_attempt_observation_sha256"] = (
                    typed_observation_id["receipt_sha256"]
                )
                typed_id_transaction["current_run_observation_sha256"] = (
                    typed_current_id["receipt_sha256"]
                )
                typed_id_transaction["receipt_sha256"] = _receipt_sha256(
                    typed_id_transaction
                )
                typed_id_completion = copy.deepcopy(id_one_completion)
                typed_id_completion["platform_observation_receipt_sha256"] = (
                    typed_observation_id["receipt_sha256"]
                )
                typed_id_completion["post_current_observation_receipt_sha256"] = (
                    typed_current_id["receipt_sha256"]
                )
                typed_id_completion["acquisition_transaction_receipt_sha256"] = (
                    typed_id_transaction["receipt_sha256"]
                )
                typed_id_completion["completion_sha256"] = _canonical_sha256(
                    {
                        k: v
                        for k, v in typed_id_completion.items()
                        if k != "completion_sha256"
                    }
                )
                typed_id_validator = _RecoveryContractValidator(
                    self.recovery_schema,
                    self.producer_receipt,
                    self.carriers["required_report_schema"]["parent_input_profiles"][
                        "merge_status_producer_implementation_receipt"
                    ],
                    typed_observation_id,
                    id_one_delivery,
                    id_one_delivery["receipt_sha256"],
                    guarded["dependency_edge_resolution_receipt"],
                    guarded["dependency_edge_resolution_receipt"]["resolver_anchor"],
                    guarded["pre_mutation_run_observation"],
                    typed_current_id,
                    typed_id_transaction,
                )
                self.assertFalse(
                    typed_id_validator.validate_completion(typed_id_completion, guarded)
                )

                typed_transaction_id = copy.deepcopy(id_one_transaction)
                typed_transaction_id["run_id"] = typed_id
                typed_transaction_id["receipt_sha256"] = _receipt_sha256(
                    typed_transaction_id
                )
                typed_transaction_completion = copy.deepcopy(id_one_completion)
                typed_transaction_completion[
                    "acquisition_transaction_receipt_sha256"
                ] = typed_transaction_id["receipt_sha256"]
                typed_transaction_completion["completion_sha256"] = _canonical_sha256(
                    {
                        k: v
                        for k, v in typed_transaction_completion.items()
                        if k != "completion_sha256"
                    }
                )
                self.assertFalse(
                    id_one_validator(
                        id_one_current, typed_transaction_id
                    ).validate_completion(typed_transaction_completion, guarded)
                )

        for typed_attempt in (True, 1.0):
            with self.subTest(guarded_attempt_type=type(typed_attempt).__name__):
                typed_observation = copy.deepcopy(guarded_observation)
                typed_observation["run_object"]["run_attempt"] = typed_attempt
                typed_observation["run_object_sha256"] = _canonical_sha256(
                    typed_observation["run_object"]
                )
                typed_observation["receipt_sha256"] = _receipt_sha256(typed_observation)
                typed_current = copy.deepcopy(guarded_current_observation)
                typed_current["run_object"]["run_attempt"] = typed_attempt
                typed_current["run_object_sha256"] = _canonical_sha256(
                    typed_current["run_object"]
                )
                typed_current["receipt_sha256"] = _receipt_sha256(typed_current)
                typed_transaction = copy.deepcopy(guarded_transaction)
                typed_transaction["exact_attempt_observation_sha256"] = (
                    typed_observation["receipt_sha256"]
                )
                typed_transaction["current_run_observation_sha256"] = typed_current[
                    "receipt_sha256"
                ]
                typed_transaction["receipt_sha256"] = _receipt_sha256(typed_transaction)
                typed_completion = copy.deepcopy(guarded_completion)
                typed_completion["observed_run_attempt"] = typed_attempt
                typed_completion["platform_observation_receipt_sha256"] = (
                    typed_observation["receipt_sha256"]
                )
                typed_completion["post_current_observation_receipt_sha256"] = (
                    typed_current["receipt_sha256"]
                )
                typed_completion["acquisition_transaction_receipt_sha256"] = (
                    typed_transaction["receipt_sha256"]
                )
                typed_completion["completion_sha256"] = _canonical_sha256(
                    {
                        k: v
                        for k, v in typed_completion.items()
                        if k != "completion_sha256"
                    }
                )
                typed_validator = _RecoveryContractValidator(
                    self.recovery_schema,
                    self.producer_receipt,
                    self.carriers["required_report_schema"]["parent_input_profiles"][
                        "merge_status_producer_implementation_receipt"
                    ],
                    typed_observation,
                    guarded_delivery,
                    guarded_delivery["receipt_sha256"],
                    guarded["dependency_edge_resolution_receipt"],
                    guarded["dependency_edge_resolution_receipt"]["resolver_anchor"],
                    guarded["pre_mutation_run_observation"],
                    typed_current,
                    typed_transaction,
                )
                self.assertFalse(
                    typed_validator.validate_completion(typed_completion, guarded)
                )

        forged_guarded_current = copy.deepcopy(guarded_current_observation)
        forged_guarded_current["run_object"].update(
            repository="octo/forged",
            run_attempt=7,
            head_sha="9" * 40,
            workflow_sha="9" * 40,
            run_ref="refs/heads/forged",
            job_workflow_ref="octo/forged/.github/workflows/x.yml@refs/heads/forged",
        )
        forged_guarded_current["run_object_sha256"] = _canonical_sha256(
            forged_guarded_current["run_object"]
        )
        forged_guarded_current["receipt_sha256"] = _receipt_sha256(
            forged_guarded_current
        )
        forged_guarded_transaction = copy.deepcopy(guarded_transaction)
        forged_guarded_transaction["current_run_observation_sha256"] = (
            forged_guarded_current["receipt_sha256"]
        )
        forged_guarded_transaction["receipt_sha256"] = _receipt_sha256(
            forged_guarded_transaction
        )
        forged_guarded_completion = copy.deepcopy(guarded_completion)
        forged_guarded_completion["post_current_observation_receipt_sha256"] = (
            forged_guarded_current["receipt_sha256"]
        )
        forged_guarded_completion["acquisition_transaction_receipt_sha256"] = (
            forged_guarded_transaction["receipt_sha256"]
        )
        forged_guarded_completion["completion_sha256"] = _canonical_sha256(
            {
                k: v
                for k, v in forged_guarded_completion.items()
                if k != "completion_sha256"
            }
        )
        forged_guarded_validator = _RecoveryContractValidator(
            self.recovery_schema,
            self.producer_receipt,
            self.carriers["required_report_schema"]["parent_input_profiles"][
                "merge_status_producer_implementation_receipt"
            ],
            guarded_observation,
            guarded_delivery,
            guarded_delivery["receipt_sha256"],
            guarded["dependency_edge_resolution_receipt"],
            guarded["dependency_edge_resolution_receipt"]["resolver_anchor"],
            guarded["pre_mutation_run_observation"],
            forged_guarded_current,
            forged_guarded_transaction,
        )
        self.assertFalse(
            forged_guarded_validator.validate_completion(
                forged_guarded_completion, guarded
            )
        )

        arbitrary_guarded_transaction = copy.deepcopy(guarded_transaction)
        arbitrary_guarded_transaction.update(
            owner="candidate", no_intervening_rerun=False
        )
        arbitrary_guarded_transaction["receipt_sha256"] = _receipt_sha256(
            arbitrary_guarded_transaction
        )
        arbitrary_transaction_completion = copy.deepcopy(guarded_completion)
        arbitrary_transaction_completion["acquisition_transaction_receipt_sha256"] = (
            arbitrary_guarded_transaction["receipt_sha256"]
        )
        arbitrary_transaction_completion["completion_sha256"] = _canonical_sha256(
            {
                k: v
                for k, v in arbitrary_transaction_completion.items()
                if k != "completion_sha256"
            }
        )
        arbitrary_transaction_validator = _RecoveryContractValidator(
            self.recovery_schema,
            self.producer_receipt,
            self.carriers["required_report_schema"]["parent_input_profiles"][
                "merge_status_producer_implementation_receipt"
            ],
            guarded_observation,
            guarded_delivery,
            guarded_delivery["receipt_sha256"],
            guarded["dependency_edge_resolution_receipt"],
            guarded["dependency_edge_resolution_receipt"]["resolver_anchor"],
            guarded["pre_mutation_run_observation"],
            guarded_current_observation,
            arbitrary_guarded_transaction,
        )
        self.assertFalse(
            arbitrary_transaction_validator.validate_completion(
                arbitrary_transaction_completion, guarded
            )
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
                    guarded["dependency_edge_resolution_receipt"],
                    guarded["dependency_edge_resolution_receipt"]["resolver_anchor"],
                    guarded["pre_mutation_run_observation"],
                    guarded_current_observation,
                    guarded_transaction,
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
            guarded["dependency_edge_resolution_receipt"],
            guarded["dependency_edge_resolution_receipt"]["resolver_anchor"],
            guarded["pre_mutation_run_observation"],
            guarded_current_observation,
            guarded_transaction,
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
            guarded["dependency_edge_resolution_receipt"],
            guarded["dependency_edge_resolution_receipt"]["resolver_anchor"],
            guarded["pre_mutation_run_observation"],
            guarded_current_observation,
            guarded_transaction,
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

    def test_existing_rerun_modes_repository_and_attempt_chain(self) -> None:
        def rebuild_contract(contract: dict[str, object]) -> None:
            contract["repeat_safety"]["operation_identity_sha256"] = _canonical_sha256(
                contract["operation_intent"]
            )
            contract["preflight_sha256"] = _canonical_sha256(
                {k: v for k, v in contract.items() if k != "preflight_sha256"}
            )

        def rebuild_delivery(receipt: dict[str, object]) -> None:
            receipt["receipt_sha256"] = _receipt_sha256(receipt)

        def rebuild_observation(
            receipt: dict[str, object],
            contract: dict[str, object],
            delivery: dict[str, object],
        ) -> None:
            receipt["preflight_sha256"] = contract["preflight_sha256"]
            receipt["operation_identity_sha256"] = contract["repeat_safety"][
                "operation_identity_sha256"
            ]
            receipt["dispatch_delivery_receipt_sha256"] = delivery["receipt_sha256"]
            receipt["run_object_sha256"] = _canonical_sha256(receipt["run_object"])
            receipt["receipt_sha256"] = _receipt_sha256(receipt)

        def rebuild_completion(
            receipt: dict[str, object],
            contract: dict[str, object],
            delivery: dict[str, object] | None = None,
            observation: dict[str, object] | None = None,
            current: dict[str, object] | None = None,
            transaction: dict[str, object] | None = None,
        ) -> None:
            receipt["preflight_sha256"] = contract["preflight_sha256"]
            receipt["pre_mutation_observation_sha256"] = contract[
                "pre_mutation_run_observation"
            ]["receipt_sha256"]
            if delivery is not None:
                receipt["dispatch_delivery_receipt_sha256"] = delivery["receipt_sha256"]
            if observation is not None:
                receipt["platform_observation_receipt_sha256"] = observation[
                    "receipt_sha256"
                ]
            if current is not None:
                receipt["post_current_observation_receipt_sha256"] = current[
                    "receipt_sha256"
                ]
            if transaction is not None:
                receipt["acquisition_transaction_receipt_sha256"] = transaction[
                    "receipt_sha256"
                ]
            receipt["completion_sha256"] = _canonical_sha256(
                {k: v for k, v in receipt.items() if k != "completion_sha256"}
            )

        def post_chain(
            contract: dict[str, object],
            delivery: dict[str, object],
            observation: dict[str, object],
        ) -> tuple[dict[str, object], dict[str, object]]:
            current = copy.deepcopy(observation)
            current["query_endpoint"] = (
                f"/repos/{contract['repository']}/actions/runs/"
                f"{observation['returned_run_id']}"
            )
            current["receipt_sha256"] = _receipt_sha256(current)
            transaction = {
                "owner": "parent-orchestrator",
                "status": "complete",
                "profile": "github-codex-recovery-acquisition-transaction-v1",
                "repository": contract["repository"],
                "run_id": observation["returned_run_id"],
                "pre_observation_sha256": contract["pre_mutation_run_observation"][
                    "receipt_sha256"
                ],
                "delivery_receipt_sha256": delivery["receipt_sha256"],
                "exact_attempt_observation_sha256": observation["receipt_sha256"],
                "current_run_observation_sha256": current["receipt_sha256"],
                "pre_response_date": contract["pre_mutation_run_observation"][
                    "response_date"
                ],
                "pre_acquired_at": contract["pre_mutation_run_observation"][
                    "observed_at"
                ],
                "post_server_time": delivery["request_server_time"],
                "exact_response_date": observation["response_date"],
                "exact_acquired_at": observation["run_object"]["observed_at"],
                "current_response_date": current["response_date"],
                "current_acquired_at": current["run_object"]["observed_at"],
                "no_intervening_rerun": True,
                "receipt_sha256": "",
            }
            transaction["receipt_sha256"] = _receipt_sha256(transaction)
            return current, transaction

        def validator(
            contract: dict[str, object],
            delivery: dict[str, object],
            observation: dict[str, object],
            *,
            producer: dict[str, object] | None = None,
            expected_resolution: dict[str, object] | None = None,
            expected_resolver: dict[str, object] | None = None,
            current: dict[str, object] | None = None,
            transaction: dict[str, object] | None = None,
        ) -> _RecoveryContractValidator:
            return _RecoveryContractValidator(
                self.recovery_schema,
                producer or self.producer_receipt,
                self.carriers["required_report_schema"]["parent_input_profiles"][
                    "merge_status_producer_implementation_receipt"
                ],
                observation,
                delivery,
                delivery["receipt_sha256"],
                expected_resolution
                or self.recovery_contract["dependency_edge_resolution_receipt"],
                expected_resolver
                or self.recovery_contract["dependency_edge_resolution_receipt"][
                    "resolver_anchor"
                ],
                self.recovery_contract["pre_mutation_run_observation"],
                current or self.post_current_observation,
                transaction or self.acquisition_transaction,
            )

        failed_contract = copy.deepcopy(self.recovery_contract)
        failed_contract["operation_intent"]["kind"] = "existing-run-rerun-failed-jobs"
        rebuild_contract(failed_contract)
        self.assertNotEqual(
            self.recovery_contract["repeat_safety"]["operation_identity_sha256"],
            failed_contract["repeat_safety"]["operation_identity_sha256"],
        )
        failed_delivery = copy.deepcopy(self.dispatch_delivery_receipt)
        failed_delivery.update(
            delivery_status="existing-run-rerun-failed-jobs",
            request_endpoint=(
                "/repos/octo/review-fixture/actions/runs/801/rerun-failed-jobs"
            ),
        )
        rebuild_delivery(failed_delivery)
        failed_observation = copy.deepcopy(self.platform_observation)
        rebuild_observation(failed_observation, failed_contract, failed_delivery)
        failed_current, failed_transaction = post_chain(
            failed_contract, failed_delivery, failed_observation
        )
        failed_completion = copy.deepcopy(self.completion_receipt)
        rebuild_completion(
            failed_completion,
            failed_contract,
            failed_delivery,
            failed_observation,
            failed_current,
            failed_transaction,
        )
        failed_validator = validator(
            failed_contract,
            failed_delivery,
            failed_observation,
            current=failed_current,
            transaction=failed_transaction,
        )
        self.assertTrue(failed_validator.validate_preflight(failed_contract))
        self.assertTrue(
            failed_validator.validate_completion(failed_completion, failed_contract)
        )

        current_one_second_behind = copy.deepcopy(failed_current)
        current_one_second_behind["run_object"]["updated_at"] = "2026-08-26T10:00:44Z"
        current_one_second_behind["run_object_sha256"] = _canonical_sha256(
            current_one_second_behind["run_object"]
        )
        current_one_second_behind["receipt_sha256"] = _receipt_sha256(
            current_one_second_behind
        )
        asymmetric_transaction = copy.deepcopy(failed_transaction)
        asymmetric_transaction["current_run_observation_sha256"] = (
            current_one_second_behind["receipt_sha256"]
        )
        asymmetric_transaction["receipt_sha256"] = _receipt_sha256(
            asymmetric_transaction
        )
        asymmetric_completion = copy.deepcopy(failed_completion)
        rebuild_completion(
            asymmetric_completion,
            failed_contract,
            failed_delivery,
            failed_observation,
            current_one_second_behind,
            asymmetric_transaction,
        )
        self.assertTrue(
            validator(
                failed_contract,
                failed_delivery,
                failed_observation,
                current=current_one_second_behind,
                transaction=asymmetric_transaction,
            ).validate_completion(asymmetric_completion, failed_contract)
        )

        invalid_current_time = copy.deepcopy(current_one_second_behind)
        invalid_current_time["run_object"]["updated_at"] = "2026-08-26T10:00:29Z"
        invalid_current_time["run_object_sha256"] = _canonical_sha256(
            invalid_current_time["run_object"]
        )
        invalid_current_time["receipt_sha256"] = _receipt_sha256(invalid_current_time)
        invalid_transaction = copy.deepcopy(asymmetric_transaction)
        invalid_transaction["current_run_observation_sha256"] = invalid_current_time[
            "receipt_sha256"
        ]
        invalid_transaction["receipt_sha256"] = _receipt_sha256(invalid_transaction)
        invalid_completion = copy.deepcopy(asymmetric_completion)
        rebuild_completion(
            invalid_completion,
            failed_contract,
            failed_delivery,
            failed_observation,
            invalid_current_time,
            invalid_transaction,
        )
        self.assertFalse(
            validator(
                failed_contract,
                failed_delivery,
                failed_observation,
                current=invalid_current_time,
                transaction=invalid_transaction,
            ).validate_completion(invalid_completion, failed_contract)
        )

        for name, mutate in {
            "cross-mode-endpoint": lambda value: value.update(
                request_endpoint="/repos/octo/review-fixture/actions/runs/801/rerun"
            ),
            "wrong-status": lambda value: value.update(response_status=200),
            "body-present": lambda value: value.update(
                request_body={},
                request_body_encoding="rfc8785-semantic-json-v1",
                request_body_sha256=_canonical_sha256({}),
            ),
        }.items():
            with self.subTest(delivery=name):
                attacked = copy.deepcopy(failed_delivery)
                mutate(attacked)
                rebuild_delivery(attacked)
                attacked_observation = copy.deepcopy(failed_observation)
                rebuild_observation(attacked_observation, failed_contract, attacked)
                attacked_current, attacked_transaction = post_chain(
                    failed_contract, attacked, attacked_observation
                )
                attacked_completion = copy.deepcopy(failed_completion)
                rebuild_completion(
                    attacked_completion,
                    failed_contract,
                    attacked,
                    attacked_observation,
                    attacked_current,
                    attacked_transaction,
                )
                self.assertFalse(
                    validator(
                        failed_contract,
                        attacked,
                        attacked_observation,
                        current=attacked_current,
                        transaction=attacked_transaction,
                    ).validate_completion(attacked_completion, failed_contract)
                )

        reverse_cross_mode = copy.deepcopy(self.dispatch_delivery_receipt)
        reverse_cross_mode.update(
            delivery_status="existing-run-rerun-full",
            request_endpoint=(
                "/repos/octo/review-fixture/actions/runs/801/rerun-failed-jobs"
            ),
        )
        rebuild_delivery(reverse_cross_mode)
        reverse_observation = copy.deepcopy(self.platform_observation)
        rebuild_observation(
            reverse_observation, self.recovery_contract, reverse_cross_mode
        )
        reverse_current, reverse_transaction = post_chain(
            self.recovery_contract, reverse_cross_mode, reverse_observation
        )
        reverse_completion = copy.deepcopy(self.completion_receipt)
        rebuild_completion(
            reverse_completion,
            self.recovery_contract,
            reverse_cross_mode,
            reverse_observation,
            reverse_current,
            reverse_transaction,
        )
        self.assertFalse(
            validator(
                self.recovery_contract,
                reverse_cross_mode,
                reverse_observation,
                current=reverse_current,
                transaction=reverse_transaction,
            ).validate_completion(reverse_completion, self.recovery_contract)
        )

        for name, mutate in {
            "no-increment": lambda run: run.update(run_attempt=1),
            "skipped-attempt": lambda run: run.update(run_attempt=3),
            "old-snapshot": lambda run: run.update(observed_at="2026-08-26T09:58:00Z"),
            "wrong-previous": lambda run: run.update(
                previous_attempt_url=(
                    "https://api.github.com/repos/octo/review-fixture/actions/"
                    "runs/801/attempts/9"
                )
            ),
        }.items():
            with self.subTest(observation=name):
                attacked = copy.deepcopy(failed_observation)
                mutate(attacked["run_object"])
                rebuild_observation(attacked, failed_contract, failed_delivery)
                attacked_current, attacked_transaction = post_chain(
                    failed_contract, failed_delivery, attacked
                )
                attacked_completion = copy.deepcopy(failed_completion)
                rebuild_completion(
                    attacked_completion,
                    failed_contract,
                    failed_delivery,
                    attacked,
                    attacked_current,
                    attacked_transaction,
                )
                self.assertFalse(
                    validator(
                        failed_contract,
                        failed_delivery,
                        attacked,
                        current=attacked_current,
                        transaction=attacked_transaction,
                    ).validate_completion(attacked_completion, failed_contract)
                )

        current_endpoint = copy.deepcopy(failed_observation)
        current_endpoint["query_endpoint"] = (
            "/repos/octo/review-fixture/actions/runs/801"
        )
        rebuild_observation(current_endpoint, failed_contract, failed_delivery)
        endpoint_current, endpoint_transaction = post_chain(
            failed_contract, failed_delivery, current_endpoint
        )
        current_completion = copy.deepcopy(failed_completion)
        rebuild_completion(
            current_completion,
            failed_contract,
            failed_delivery,
            current_endpoint,
            endpoint_current,
            endpoint_transaction,
        )
        self.assertFalse(
            validator(
                failed_contract,
                failed_delivery,
                current_endpoint,
                current=endpoint_current,
                transaction=endpoint_transaction,
            ).validate_completion(current_completion, failed_contract)
        )

        stale_delivery = copy.deepcopy(failed_delivery)
        stale_delivery["request_server_time"] = "2026-08-26T11:00:00Z"
        rebuild_delivery(stale_delivery)
        stale_historical_attempt = copy.deepcopy(failed_observation)
        stale_historical_attempt["response_date"] = "2026-08-26T11:01:00Z"
        stale_historical_attempt["run_object"]["observed_at"] = "2026-08-26T11:01:00Z"
        rebuild_observation(stale_historical_attempt, failed_contract, stale_delivery)
        stale_current, stale_transaction = post_chain(
            failed_contract, stale_delivery, stale_historical_attempt
        )
        stale_completion = copy.deepcopy(failed_completion)
        rebuild_completion(
            stale_completion,
            failed_contract,
            stale_delivery,
            stale_historical_attempt,
            stale_current,
            stale_transaction,
        )
        self.assertFalse(
            validator(
                failed_contract,
                stale_delivery,
                stale_historical_attempt,
                current=stale_current,
                transaction=stale_transaction,
            ).validate_completion(stale_completion, failed_contract)
        )

        legacy = copy.deepcopy(self.recovery_contract)
        legacy["operation_intent"]["kind"] = "existing-run-rerun"
        rebuild_contract(legacy)
        self.assertFalse(self.recovery_validator.validate_preflight(legacy))
        for unsupported in ("existing-run-rerun-job", "existing-run-rerun-debug"):
            invalid = copy.deepcopy(self.recovery_contract)
            invalid["operation_intent"]["kind"] = unsupported
            rebuild_contract(invalid)
            self.assertFalse(self.recovery_validator.validate_preflight(invalid))

        forged_producer = copy.deepcopy(self.producer_receipt)
        forged_producer["repository"] = "octo/other-repository"
        forged_producer["receipt_sha256"] = _receipt_sha256(forged_producer)
        coupled = copy.deepcopy(self.recovery_contract)
        coupled["implementation_receipt_identity"].update(
            repository=forged_producer["repository"],
            receipt_sha256=forged_producer["receipt_sha256"],
        )
        coupled["dependency_edge_resolution_receipt"][
            "implementation_receipt_sha256"
        ] = forged_producer["receipt_sha256"]
        coupled["dependency_edge_resolution_receipt"]["receipt_sha256"] = (
            _receipt_sha256(coupled["dependency_edge_resolution_receipt"])
        )
        rebuild_contract(coupled)
        self.assertFalse(
            validator(
                coupled,
                self.dispatch_delivery_receipt,
                self.platform_observation,
                producer=forged_producer,
                expected_resolution=coupled["dependency_edge_resolution_receipt"],
            ).validate_preflight(coupled)
        )

        downstream_delivery = copy.deepcopy(self.dispatch_delivery_receipt)
        downstream_delivery["repository"] = "octo/other-repository"
        downstream_delivery["request_endpoint"] = (
            "/repos/octo/other-repository/actions/runs/801/rerun"
        )
        rebuild_delivery(downstream_delivery)
        downstream_observation = copy.deepcopy(self.platform_observation)
        downstream_observation["query_repository"] = "octo/other-repository"
        downstream_observation["query_endpoint"] = (
            "/repos/octo/other-repository/actions/runs/801/attempts/2"
        )
        downstream_observation["run_object"]["repository"] = "octo/other-repository"
        rebuild_observation(
            downstream_observation, self.recovery_contract, downstream_delivery
        )
        downstream_completion = copy.deepcopy(self.completion_receipt)
        downstream_completion["observed_repository"] = "octo/other-repository"
        rebuild_completion(downstream_completion, self.recovery_contract)
        self.assertFalse(
            validator(
                self.recovery_contract,
                downstream_delivery,
                downstream_observation,
            ).validate_completion(downstream_completion, self.recovery_contract)
        )

    def test_recovery_resolution_receipt_is_external_and_full_entry_bound(self) -> None:
        def delete_reference_and_edge(receipt: dict[str, object]) -> None:
            workflow_record = next(
                record
                for record in receipt["records"]
                if record["source_entry"]["kind"] == "workflow"
            )
            workflow_record["discovered_references"] = []
            workflow_record["discovered_reference_count"] = 0
            workflow_record["record_sha256"] = _canonical_sha256(
                {k: v for k, v in workflow_record.items() if k != "record_sha256"}
            )
            receipt["records_sha256"] = _canonical_sha256(receipt["records"])
            receipt["edges"] = []
            receipt["edge_count"] = 0
            receipt["edges_sha256"] = _canonical_sha256([])

        def delete_edge_only(receipt: dict[str, object]) -> None:
            receipt["edges"] = []
            receipt["edge_count"] = 0
            receipt["edges_sha256"] = _canonical_sha256([])

        def duplicate_reference(receipt: dict[str, object]) -> None:
            workflow_record = next(
                record
                for record in receipt["records"]
                if record["source_entry"]["kind"] == "workflow"
            )
            workflow_record["discovered_references"].append(
                copy.deepcopy(workflow_record["discovered_references"][0])
            )
            workflow_record["discovered_reference_count"] = 2
            workflow_record["record_sha256"] = _canonical_sha256(
                {k: v for k, v in workflow_record.items() if k != "record_sha256"}
            )
            receipt["records_sha256"] = _canonical_sha256(receipt["records"])

        for name, mutate in {
            "invented-resolver": lambda receipt: receipt["resolver_anchor"].update(
                repository="octo/invented-resolver"
            ),
            "missing-record": lambda receipt: receipt.update(
                records=[], record_count=0, records_sha256=_canonical_sha256([])
            ),
            "candidate-entry": lambda receipt: receipt["records"][0][
                "source_entry"
            ].update(repository="octo/review-fixture", commit="d" * 40),
            "coupled-delete-reference-and-edge": delete_reference_and_edge,
            "edge-omitted": delete_edge_only,
            "duplicate-reference": duplicate_reference,
        }.items():
            with self.subTest(attack=name):
                attacked = copy.deepcopy(self.recovery_contract)
                receipt = attacked["dependency_edge_resolution_receipt"]
                mutate(receipt)
                if isinstance(receipt.get("resolver_anchor"), dict):
                    receipt["resolver_anchor"]["receipt_sha256"] = _receipt_sha256(
                        receipt["resolver_anchor"]
                    )
                receipt["receipt_sha256"] = _receipt_sha256(receipt)
                attacked["preflight_sha256"] = _canonical_sha256(
                    {k: v for k, v in attacked.items() if k != "preflight_sha256"}
                )
                self.assertFalse(self.recovery_validator.validate_preflight(attacked))

        for name, mutate in {
            "coupled-invented-anchor": lambda anchor: anchor.update(
                repository="octo/invented-resolver",
                commit="9" * 40,
                path="resolver/forged.py",
                sha256="9" * 64,
            ),
            "coupled-installed-candidate-anchor": lambda anchor: anchor.update(
                kind="installed-trusted-release",
                repository="octo/review-fixture",
                commit="d" * 40,
                installed_release_manifest_sha256="9" * 64,
            ),
        }.items():
            with self.subTest(coupled_anchor=name):
                attacked = copy.deepcopy(self.recovery_contract)
                receipt = attacked["dependency_edge_resolution_receipt"]
                mutate(receipt["resolver_anchor"])
                receipt["resolver_anchor"]["receipt_sha256"] = _receipt_sha256(
                    receipt["resolver_anchor"]
                )
                receipt["receipt_sha256"] = _receipt_sha256(receipt)
                attacked["preflight_sha256"] = _canonical_sha256(
                    {k: v for k, v in attacked.items() if k != "preflight_sha256"}
                )
                validator = _RecoveryContractValidator(
                    self.recovery_schema,
                    self.producer_receipt,
                    self.carriers["required_report_schema"]["parent_input_profiles"][
                        "merge_status_producer_implementation_receipt"
                    ],
                    self.platform_observation,
                    self.dispatch_delivery_receipt,
                    self.dispatch_delivery_receipt["receipt_sha256"],
                    receipt,
                    self.recovery_contract["dependency_edge_resolution_receipt"][
                        "resolver_anchor"
                    ],
                    self.recovery_contract["pre_mutation_run_observation"],
                    self.post_current_observation,
                    self.acquisition_transaction,
                )
                self.assertFalse(validator.validate_preflight(attacked))

    def test_recovery_composes_with_closed_producer_profile(self) -> None:
        module_name = (
            f"{__package__}.test_github_terminal_carriers"
            if __package__
            else "test_github_terminal_carriers"
        )
        terminal_module = importlib.import_module(module_name)
        terminal_case_class = terminal_module.GitHubTerminalCarrierContractTest
        terminal_case_class.setUpClass()
        terminal_case = terminal_case_class()
        terminal_validator = terminal_case._validator_with_complete_snapshot(
            terminal_case.merge_complete_pr_parent_snapshot
        )
        composed_receipt = copy.deepcopy(
            terminal_case.merge_status_producer_implementation_receipt
        )
        for field in (
            "workflow_repository",
            "workflow_path",
            "workflow_sha",
            "workflow_ref",
            "workflow_ref_identity",
            "job_workflow_ref",
            "job_workflow_ref_identity",
            "implementation_closure_complete",
            "implementation_closure",
            "implementation_closure_count",
            "implementation_closure_sha256",
        ):
            composed_receipt[field] = copy.deepcopy(self.producer_receipt[field])
        composed_receipt["receipt_sha256"] = _receipt_sha256(composed_receipt)
        terminal_validator.merge_status_producer_implementation_receipt = (
            composed_receipt
        )
        report = copy.deepcopy(terminal_case.grammar["report_bases"]["merge_status"])
        self.assertTrue(
            terminal_validator._merge_status_producer_implementation_matches(report)
        )
        self.assertTrue(
            self.recovery_validator.validate_preflight(self.recovery_contract)
        )

    def test_recovery_rejects_malformed_producer_closure_after_coupled_rehash(
        self,
    ) -> None:
        def rebuild(
            producer: dict[str, object], contract: dict[str, object]
        ) -> _RecoveryContractValidator:
            producer["implementation_closure_sha256"] = _canonical_sha256(
                producer["implementation_closure"]
            )
            producer["receipt_sha256"] = _receipt_sha256(producer)
            contract["implementation_receipt_identity"]["receipt_sha256"] = producer[
                "receipt_sha256"
            ]
            resolution = contract["dependency_edge_resolution_receipt"]
            resolution["implementation_receipt_sha256"] = producer["receipt_sha256"]
            resolution["receipt_sha256"] = _receipt_sha256(resolution)
            contract["preflight_sha256"] = _canonical_sha256(
                {k: v for k, v in contract.items() if k != "preflight_sha256"}
            )
            return _RecoveryContractValidator(
                self.recovery_schema,
                producer,
                self.carriers["required_report_schema"]["parent_input_profiles"][
                    "merge_status_producer_implementation_receipt"
                ],
                self.platform_observation,
                self.dispatch_delivery_receipt,
                self.dispatch_delivery_receipt["receipt_sha256"],
                resolution,
                self.recovery_contract["dependency_edge_resolution_receipt"][
                    "resolver_anchor"
                ],
                self.recovery_contract["pre_mutation_run_observation"],
                self.post_current_observation,
                self.acquisition_transaction,
            )

        def mutate_non_root_entry(
            producer: dict[str, object],
            contract: dict[str, object],
            mutate: object,
        ) -> None:
            old_entry = copy.deepcopy(producer["implementation_closure"][1])
            new_entry = copy.deepcopy(old_entry)
            mutate(new_entry)
            producer["implementation_closure"][1] = new_entry
            resolution = contract["dependency_edge_resolution_receipt"]
            for record in resolution["records"]:
                if record["source_entry"] == old_entry:
                    record["source_entry"] = copy.deepcopy(new_entry)
                    record["source_sha256"] = new_entry["blob_sha256"]
                for reference in record["discovered_references"]:
                    if reference["target_entry"] == old_entry:
                        reference["target_entry"] = copy.deepcopy(new_entry)
                record["record_sha256"] = _canonical_sha256(
                    {k: v for k, v in record.items() if k != "record_sha256"}
                )
            resolution["records"].sort(
                key=lambda record: (
                    record["source_entry"].get("repository", ""),
                    record["source_entry"].get("commit", ""),
                    record["source_entry"].get("path", ""),
                    record["source_entry"].get("kind", ""),
                    record["source_entry"].get("blob_sha256", ""),
                )
            )
            resolution["records_sha256"] = _canonical_sha256(resolution["records"])
            for edge in resolution["edges"]:
                if edge["source_entry"] == old_entry:
                    edge["source_entry"] = copy.deepcopy(new_entry)
                if edge["target_entry"] == old_entry:
                    edge["target_entry"] = copy.deepcopy(new_entry)
            resolution["edges"].sort(
                key=lambda edge: (
                    edge["source_entry"].get("repository", ""),
                    edge["source_entry"].get("commit", ""),
                    edge["source_entry"].get("path", ""),
                    edge["source_entry"].get("kind", ""),
                    edge["source_entry"].get("blob_sha256", ""),
                    edge["reference"],
                    edge["target_entry"].get("repository", ""),
                    edge["target_entry"].get("commit", ""),
                    edge["target_entry"].get("path", ""),
                    edge["target_entry"].get("kind", ""),
                    edge["target_entry"].get("blob_sha256", ""),
                )
            )
            resolution["edges_sha256"] = _canonical_sha256(resolution["edges"])

        for name, mutate in {
            "invalid-kind": lambda entry: entry.update(kind="local-action"),
            "unsafe-path": lambda entry: entry.update(path="actions/../action.yml"),
            "invalid-repository": lambda entry: entry.update(repository="owner/"),
            "invalid-commit-sha": lambda entry: entry.update(commit="bad"),
            "invalid-blob-sha": lambda entry: entry.update(blob_sha256="bad"),
            "extra-entry-field": lambda entry: entry.update(extra=True),
        }.items():
            with self.subTest(producer_attack=name):
                producer = copy.deepcopy(self.producer_receipt)
                contract = copy.deepcopy(self.recovery_contract)
                mutate_non_root_entry(producer, contract, mutate)
                validator = rebuild(producer, contract)
                self.assertFalse(validator.validate_preflight(contract))

        producer = copy.deepcopy(self.producer_receipt)
        contract = copy.deepcopy(self.recovery_contract)
        producer["run_ref"] = "feature/review"
        for raw_field, identity_field in (
            ("workflow_ref", "workflow_ref_identity"),
            ("job_workflow_ref", "job_workflow_ref_identity"),
        ):
            producer[identity_field]["ref"] = producer["run_ref"]
            producer[raw_field] = (
                f"{producer[identity_field]['repository']}/"
                f"{producer[identity_field]['path']}@{producer['run_ref']}"
            )
        contract["implementation_receipt_identity"]["run_ref"] = producer["run_ref"]
        contract["operation_intent"]["ref"] = producer["run_ref"]
        contract["repeat_safety"]["operation_identity_sha256"] = _canonical_sha256(
            contract["operation_intent"]
        )
        attacked_before = contract["pre_mutation_run_observation"]
        attacked_before["run_ref"] = producer["run_ref"]
        attacked_before["workflow_ref"] = producer["workflow_ref"]
        attacked_before["job_workflow_ref"] = producer["job_workflow_ref"]
        attacked_before["receipt_sha256"] = _receipt_sha256(attacked_before)
        validator = rebuild(producer, contract)
        validator.expected_pre_mutation_observation = copy.deepcopy(attacked_before)
        self.assertFalse(validator.validate_preflight(contract))

        for name, mutate in {
            "float-count": lambda producer: producer.update(
                implementation_closure_count=2.0
            ),
            "tuple-closure": lambda producer: producer.update(
                implementation_closure=tuple(producer["implementation_closure"])
            ),
        }.items():
            with self.subTest(producer_shape_attack=name):
                producer = copy.deepcopy(self.producer_receipt)
                contract = copy.deepcopy(self.recovery_contract)
                mutate(producer)
                validator = rebuild(producer, contract)
                self.assertFalse(validator.validate_preflight(contract))

        for name, mutate in {
            "malformed-nested-entry": lambda producer: producer[
                "workflow_ref_identity"
            ]["entry"].update(extra=True),
            "unsorted-closure": lambda producer: producer[
                "implementation_closure"
            ].reverse(),
        }.items():
            with self.subTest(producer_attack=name):
                producer = copy.deepcopy(self.producer_receipt)
                contract = copy.deepcopy(self.recovery_contract)
                mutate(producer)
                validator = rebuild(producer, contract)
                self.assertFalse(validator.validate_preflight(contract))

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
