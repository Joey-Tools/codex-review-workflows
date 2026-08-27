from __future__ import annotations

import copy
import datetime
import hashlib
import importlib
import json
import pathlib
import re
import unittest
import urllib.parse

SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
REFERENCES = SKILL_ROOT / "references"
FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
REPOSITORY_COMPONENT = re.compile(r"[A-Za-z0-9._-]{1,100}\Z")
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_CANONICAL_JSON_DEPTH = 256
MAX_CANONICAL_JSON_NODES = 100_000
MAX_CANONICAL_JSON_STRING_UTF8_BYTES = 1 << 20
MAX_CANONICAL_JSON_AGGREGATE_UTF8_BYTES = 16 << 20
VALIDATION_EXCEPTIONS = (
    AttributeError,
    IndexError,
    KeyError,
    OverflowError,
    RecursionError,
    TypeError,
    ValueError,
)


def _repository_identity(value: object) -> str | None:
    """Return GitHub's ASCII case-insensitive owner/name identity."""

    if not isinstance(value, str) or not value.isascii():
        return None
    parts = value.split("/")
    if (
        len(parts) != 2
        or any(REPOSITORY_COMPONENT.fullmatch(part) is None for part in parts)
        or any(part in {".", ".."} for part in parts)
    ):
        return None
    return "/".join(part.lower() for part in parts)


def _same_repository(left: object, right: object) -> bool:
    left_identity = _repository_identity(left)
    return left_identity is not None and left_identity == _repository_identity(right)


def _repository_selector_matches(
    reference: object, repository: object, exact_suffix: str
) -> bool:
    if (
        not isinstance(reference, str)
        or not exact_suffix
        or not reference.endswith(exact_suffix)
    ):
        return False
    return _same_repository(reference[: -len(exact_suffix)], repository)


def _same_repository_selector(left: object, right: object, exact_suffix: str) -> bool:
    if (
        not isinstance(left, str)
        or not isinstance(right, str)
        or not left.endswith(exact_suffix)
        or not right.endswith(exact_suffix)
    ):
        return False
    return _same_repository(left[: -len(exact_suffix)], right[: -len(exact_suffix)])


def _repository_selector_identity(
    reference: str, target_entry: dict[str, object]
) -> tuple[object, ...]:
    if reference.startswith(("./", "../", "$/")):
        return ("relative", reference)
    kind = target_entry["kind"]
    path = target_entry["path"]
    commit = target_entry["commit"]
    if kind == "reusable-workflow":
        suffix = f"/{path}@{commit}"
    elif kind == "action":
        action_directory = pathlib.PurePosixPath(path).parent.as_posix()
        suffix = (
            f"@{commit}" if action_directory == "." else f"/{action_directory}@{commit}"
        )
    else:
        return ("unsupported", reference)
    repository = reference[: -len(suffix)] if reference.endswith(suffix) else None
    return ("external", _repository_identity(repository), suffix)


def _has_url_control_or_space(value: str) -> bool:
    return any(
        ord(character) <= 0x20 or 0x7F <= ord(character) <= 0x9F for character in value
    )


def _repository_scoped_string_matches(
    value: object, prefix: str, repository: object, exact_suffix: str
) -> bool:
    if (
        not isinstance(value, str)
        or _has_url_control_or_space(value)
        or not value.startswith(prefix)
        or not value.endswith(exact_suffix)
    ):
        return False
    if prefix == "https://api.github.com/repos/":
        parsed = urllib.parse.urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.netloc != "api.github.com"
            or urllib.parse.urlunsplit(parsed) != value
        ):
            return False
    repository_text = value[len(prefix) : -len(exact_suffix)]
    return _same_repository(repository_text, repository)


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def _normalize(value: str) -> str:
    return " ".join(value.split()).lower()


def _require_rfc8785_integer_domain(value: object) -> None:
    stack: list[tuple[str, object, int, int]] = [("value", value, 0, 0)]
    active_containers: set[int] = set()
    node_count = 0
    aggregate_string_bytes = 0
    while stack:
        frame_kind, current, container_depth, container_identity = stack.pop()
        if frame_kind == "iterator":
            try:
                child = next(current)  # type: ignore[arg-type]
            except StopIteration:
                active_containers.remove(container_identity)
                continue
            stack.append(("iterator", current, container_depth, container_identity))
            stack.append(("value", child, container_depth, 0))
            continue
        node_count += 1
        if node_count > MAX_CANONICAL_JSON_NODES:
            raise ValueError("canonical JSON exceeds the closed resource profile")
        if type(current) is bool or current is None:
            continue
        if type(current) is str:
            if len(current) > MAX_CANONICAL_JSON_STRING_UTF8_BYTES:
                raise ValueError("canonical JSON string exceeds the closed byte cap")
            try:
                encoded = current.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ValueError(
                    "canonical JSON strings must contain Unicode scalars"
                ) from error
            if len(encoded) > MAX_CANONICAL_JSON_STRING_UTF8_BYTES:
                raise ValueError("canonical JSON string exceeds the closed byte cap")
            aggregate_string_bytes += len(encoded)
            if aggregate_string_bytes > MAX_CANONICAL_JSON_AGGREGATE_UTF8_BYTES:
                raise ValueError("canonical JSON strings exceed the aggregate byte cap")
            continue
        if type(current) is int:
            if not -MAX_SAFE_INTEGER <= current <= MAX_SAFE_INTEGER:
                raise ValueError("integer is outside the RFC 8785 interoperable domain")
            continue
        if type(current) in {list, dict}:
            next_depth = container_depth + 1
            if next_depth > MAX_CANONICAL_JSON_DEPTH:
                raise ValueError("canonical JSON exceeds the closed resource profile")
            if node_count + len(current) > MAX_CANONICAL_JSON_NODES:
                raise ValueError("canonical JSON exceeds the closed resource profile")
            identity = id(current)
            if identity in active_containers:
                raise ValueError("canonical JSON containers must be acyclic")
            active_containers.add(identity)
            if type(current) is dict:
                for key in current:
                    if type(key) is not str or not key.isascii():
                        raise ValueError(
                            "canonical JSON object keys must be ASCII strings"
                        )
                    if len(key) > MAX_CANONICAL_JSON_STRING_UTF8_BYTES:
                        raise ValueError(
                            "canonical JSON object key exceeds the closed byte cap"
                        )
                    aggregate_string_bytes += len(key)
                    if aggregate_string_bytes > MAX_CANONICAL_JSON_AGGREGATE_UTF8_BYTES:
                        raise ValueError(
                            "canonical JSON strings exceed the aggregate byte cap"
                        )
                children = iter(current.values())
            else:
                children = iter(current)
            stack.append(("iterator", children, next_depth, identity))
            continue
        raise ValueError("canonical JSON value is outside the integer-only profile")


_MALFORMED_PARENT_INPUT = object()


def _bounded_parent_copy(value: object) -> object:
    try:
        _require_rfc8785_integer_domain(value)
        return copy.deepcopy(value)
    except VALIDATION_EXCEPTIONS:
        return _MALFORMED_PARENT_INPUT


def _canonical_sha256(value: object) -> str:
    _require_rfc8785_integer_domain(value)
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


def _type_preserving_equal(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(
            _type_preserving_equal(left[key], right[key]) for key in left
        )
    if type(left) is list:
        return len(left) == len(right) and all(
            _type_preserving_equal(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    return left == right


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
        self.producer_receipt = _bounded_parent_copy(producer_receipt)
        self.producer_receipt_fields = _bounded_parent_copy(producer_receipt_fields)
        self.platform_observation = _bounded_parent_copy(platform_observation)
        self.dispatch_delivery_receipt = _bounded_parent_copy(dispatch_delivery_receipt)
        self.expected_delivery_receipt_sha256 = expected_delivery_receipt_sha256
        self.expected_dependency_resolution_receipt = _bounded_parent_copy(
            expected_dependency_resolution_receipt
        )
        self.expected_resolver_anchor = _bounded_parent_copy(expected_resolver_anchor)
        self.expected_pre_mutation_observation = _bounded_parent_copy(
            expected_pre_mutation_observation
        )
        self.post_current_observation = _bounded_parent_copy(post_current_observation)
        self.acquisition_transaction_receipt = _bounded_parent_copy(
            acquisition_transaction_receipt
        )

    def _closed(self, value: object, profile: str) -> bool:
        return isinstance(value, dict) and set(value) == set(self.fields[profile])

    @staticmethod
    def _positive_int(value: object) -> bool:
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 < value <= MAX_SAFE_INTEGER
        )

    def _same_positive_int(self, *values: object) -> bool:
        return (
            bool(values)
            and all(self._positive_int(value) for value in values)
            and all(value == values[0] for value in values[1:])
        )

    @staticmethod
    def _nonnegative_int(value: object) -> bool:
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value <= MAX_SAFE_INTEGER
        )

    @staticmethod
    def _safe_path(value: object) -> bool:
        if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
            return False
        path = pathlib.PurePosixPath(value)
        return (
            not path.is_absolute()
            and bool(path.parts)
            and path.as_posix() == value
            and all(part not in {"", ".", ".."} for part in path.parts)
        )

    @staticmethod
    def _github_workflow_path(value: object) -> bool:
        if not isinstance(value, str):
            return False
        path = pathlib.PurePosixPath(value)
        return path.parent == pathlib.PurePosixPath(
            ".github/workflows"
        ) and path.suffix in {".yml", ".yaml"}

    @staticmethod
    def _action_manifest_directory(value: object) -> str | None:
        if not isinstance(value, str):
            return None
        if value in {"action.yml", "action.yaml"}:
            return ""
        path = pathlib.PurePosixPath(value)
        if path.name not in {"action.yml", "action.yaml"}:
            return None
        return path.parent.as_posix()

    @staticmethod
    def _repository(value: object) -> bool:
        return _repository_identity(value) is not None

    @staticmethod
    def _attempt_stable_reference(
        source_entry: dict[str, object],
        reference: str,
        target_entry: dict[str, object],
    ) -> bool:
        same_running_commit = (
            _same_repository(source_entry["repository"], target_entry["repository"])
            and source_entry["commit"] == target_entry["commit"]
        )
        if reference.startswith("./"):
            return (
                source_entry["kind"] in {"workflow", "reusable-workflow"}
                and target_entry["kind"] == "reusable-workflow"
                and same_running_commit
                and reference == f"./{target_entry['path']}"
                and _RecoveryContractValidator._github_workflow_path(
                    target_entry["path"]
                )
            )
        if reference.startswith("../"):
            return False
        if reference.startswith("$/"):
            relative_path = reference[2:]
            if (
                source_entry["kind"] in {"workflow", "reusable-workflow"}
                and target_entry["kind"] == "reusable-workflow"
            ):
                return (
                    same_running_commit
                    and relative_path == target_entry["path"]
                    and _RecoveryContractValidator._github_workflow_path(
                        target_entry["path"]
                    )
                )
            if (
                source_entry["kind"] in {"workflow", "reusable-workflow", "action"}
                and target_entry["kind"] == "action"
                and same_running_commit
            ):
                manifest_directory = (
                    _RecoveryContractValidator._action_manifest_directory(
                        target_entry["path"]
                    )
                )
                if manifest_directory is not None:
                    return relative_path == manifest_directory
            return False
        repository = target_entry["repository"]
        path = target_entry["path"]
        commit = target_entry["commit"]
        kind = target_entry["kind"]
        if (
            kind == "reusable-workflow"
            and source_entry["kind"] in {"workflow", "reusable-workflow"}
            and _RecoveryContractValidator._github_workflow_path(path)
        ):
            selector_suffix = f"/{path}@{commit}"
        elif (
            kind == "action"
            and source_entry["kind"] in {"workflow", "reusable-workflow", "action"}
            and _RecoveryContractValidator._action_manifest_directory(path)
            not in {None, ""}
        ):
            action_directory = _RecoveryContractValidator._action_manifest_directory(
                path
            )
            selector_suffix = f"/{action_directory}@{commit}"
        elif (
            kind == "action"
            and source_entry["kind"] in {"workflow", "reusable-workflow", "action"}
            and path in {"action.yml", "action.yaml"}
        ):
            selector_suffix = f"@{commit}"
        else:
            return False
        return _repository_selector_matches(reference, repository, selector_suffix)

    @staticmethod
    def _job_workflow_edge_matches(
        edge: dict[str, object],
        job_raw_ref: str,
        job_entry: dict[str, object],
    ) -> bool:
        def entry_key(entry: dict[str, object]) -> tuple[object, ...]:
            return (
                _repository_identity(entry["repository"]),
                entry["commit"],
                entry["path"],
                entry["kind"],
                entry["blob_sha256"],
            )

        if entry_key(edge["target_entry"]) != entry_key(job_entry):
            return False
        if (
            edge["source_entry"]["kind"] not in {"workflow", "reusable-workflow"}
            or job_entry["kind"] != "reusable-workflow"
        ):
            return False
        reference = edge["reference"]
        if reference.startswith(("./", "$/")):
            return (
                _same_repository(
                    edge["source_entry"]["repository"], job_entry["repository"]
                )
                and edge["source_entry"]["commit"] == job_entry["commit"]
                and job_entry["kind"] == "reusable-workflow"
            )
        suffix = f"/{job_entry['path']}@{job_entry['commit']}"
        return _repository_selector_matches(
            reference, job_entry["repository"], suffix
        ) and _repository_selector_matches(job_raw_ref, job_entry["repository"], suffix)

    def validate_preflight(self, contract: object) -> bool:
        try:
            return self._validate_preflight(contract)
        except VALIDATION_EXCEPTIONS:
            return False

    def _validate_preflight(self, contract: object) -> bool:
        try:
            for value in (
                contract,
                self.producer_receipt,
                self.expected_dependency_resolution_receipt,
                self.expected_resolver_anchor,
                self.expected_pre_mutation_observation,
            ):
                _require_rfc8785_integer_domain(value)
        except ValueError:
            return False
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
            or not self._closed(operation, "existing_run_rerun_operation_intent")
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
            _repository_identity(source["source_repository"]) is None
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
            or not _same_repository(anchor["repository"], contract["repository"])
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
            or not _same_repository(exclusion["repository"], contract["repository"])
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
        ):
            return False

        source_kind = anchor["kind"]
        source_is_candidate_repository = _same_repository(
            source["source_repository"], contract["repository"]
        )
        if source_kind == "target-branch-baseline":
            if not (
                source_is_candidate_repository
                and source["source_commit"] == exclusion["base_sha"]
            ):
                return False
        elif source_kind == "installed-trusted-release":
            if source_is_candidate_repository and source["source_commit"] in commits:
                return False
        elif source_kind == "parent-fixed-external":
            if source_is_candidate_repository:
                return False
        else:
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
            or not _same_repository(producer["repository"], contract["repository"])
            or not _same_repository(
                producer["workflow_repository"], contract["repository"]
            )
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
            or not self._same_positive_int(
                implementation["workflow_id"], producer["workflow_id"]
            )
            or not self._same_positive_int(implementation["run_id"], producer["run_id"])
            or not _type_preserving_equal(
                implementation, expected_implementation_identity
            )
            or not _type_preserving_equal(
                edges_receipt, self.expected_dependency_resolution_receipt
            )
            or not _type_preserving_equal(
                before, self.expected_pre_mutation_observation
            )
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
                _repository_identity(entry["repository"]),
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
            or (
                entry["kind"] in {"workflow", "reusable-workflow"}
                and not self._github_workflow_path(entry["path"])
            )
            or (
                entry["kind"] == "action"
                and self._action_manifest_directory(entry["path"]) is None
            )
            for entry in entries
        ):
            return False
        entry_by_key = {entry_key(item): item for item in entries}
        entry_keys = [entry_key(item) for item in entries]
        path_keys = [
            (
                _repository_identity(entry["repository"]),
                entry["commit"],
                entry["path"],
            )
            for entry in entries
        ]
        action_selector_keys = [
            (
                _repository_identity(entry["repository"]),
                entry["commit"],
                self._action_manifest_directory(entry["path"]),
            )
            for entry in entries
            if entry["kind"] == "action"
        ]
        if (
            entry_keys != sorted(entry_keys)
            or len(entry_keys) != len(set(entry_keys))
            or len(path_keys) != len(set(path_keys))
            or len(action_selector_keys) != len(set(action_selector_keys))
        ):
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
                and _same_repository(identity["repository"], entry["repository"])
                and identity["path"] == entry["path"]
                and identity["resolved_commit"] == entry["commit"]
                and isinstance(identity["ref"], str)
                and _repository_selector_matches(
                    raw,
                    identity["repository"],
                    f"/{identity['path']}@{identity['ref']}",
                )
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
            or not _same_repository(
                producer["workflow_ref_identity"]["repository"],
                producer["workflow_repository"],
            )
            or producer["workflow_ref_identity"]["path"] != producer["workflow_path"]
            or producer["workflow_ref_identity"]["resolved_commit"]
            != producer["workflow_sha"]
            or producer["workflow_ref_identity"]["ref"] != producer["run_ref"]
            or producer["workflow_ref_identity"]["entry"]["kind"] != "workflow"
            or (
                producer["job_workflow_ref_identity"]["entry"]
                == producer["workflow_ref_identity"]["entry"]
                and producer["job_workflow_ref_identity"]
                != producer["workflow_ref_identity"]
            )
            or (
                producer["job_workflow_ref_identity"]["entry"]
                != producer["workflow_ref_identity"]["entry"]
                and (
                    producer["job_workflow_ref_identity"]["entry"]["kind"]
                    != "reusable-workflow"
                )
            )
            or producer["external_implementation_id"] is not None
        ):
            return False

        workflow_entries = [
            item
            for item in producer["implementation_closure"]
            if item["kind"] == "workflow"
            and _same_repository(item["repository"], producer["workflow_repository"])
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
            or not _same_repository(edges_receipt["repository"], contract["repository"])
            or edges_receipt["head_sha"] != contract["head_sha"]
            or len(workflow_entries) != 1
            or producer["workflow_ref_identity"]["entry"] != workflow_entries[0]
            or not self._closed(resolver, "recovery_resolver_anchor")
            or resolver["owner"] != "parent-orchestrator"
            or resolver["status"] != "complete"
            or resolver["profile"] != "github-codex-recovery-resolver-anchor-v1"
            or not _type_preserving_equal(resolver, self.expected_resolver_anchor)
            or resolver["kind"]
            not in {
                "target-branch-baseline",
                "installed-trusted-release",
                "parent-fixed-external",
            }
            or FULL_SHA.fullmatch(resolver["commit"]) is None
            or _repository_identity(resolver["repository"]) is None
            or not self._safe_path(resolver["path"])
            or SHA256.fullmatch(resolver["sha256"]) is None
            or resolver["candidate_range_exclusion_sha256"]
            != _canonical_sha256(exclusion)
            or (
                resolver["kind"] == "target-branch-baseline"
                and (
                    not _same_repository(resolver["repository"], contract["repository"])
                    or resolver["commit"] != exclusion["base_sha"]
                    or resolver["installed_release_manifest_sha256"] is not None
                )
            )
            or (
                resolver["kind"] == "parent-fixed-external"
                and (
                    _same_repository(resolver["repository"], contract["repository"])
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
                _same_repository(resolver["repository"], contract["repository"])
                and resolver["commit"] in commits
            )
            or resolver["receipt_sha256"] != _receipt_sha256(resolver)
            or not isinstance(records, list)
            or not self._nonnegative_int(edges_receipt["record_count"])
            or edges_receipt["record_count"] != len(records)
            or edges_receipt["records_sha256"] != _canonical_sha256(records)
            or not isinstance(edges, list)
            or not self._nonnegative_int(edges_receipt["edge_count"])
            or edges_receipt["edge_count"] != len(edges)
            or edges_receipt["edges_sha256"] != _canonical_sha256(edges)
            or edges_receipt["receipt_sha256"] != _receipt_sha256(edges_receipt)
            or any(
                _same_repository(item["repository"], contract["repository"])
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
                        item["reference"]
                        for item in references
                        if isinstance(item, dict)
                        and "reference" in item
                        and isinstance(item.get("target_entry"), dict)
                    }
                )
                != len(references)
                or not self._nonnegative_int(record["discovered_reference_count"])
                or record["discovered_reference_count"] != len(references)
                or record["record_sha256"]
                != _canonical_sha256(
                    {k: v for k, v in record.items() if k != "record_sha256"}
                )
            ):
                return False
            record_keys.append(entry_key(source_entry))
            selector_identities: list[tuple[object, ...]] = []
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
                    or not self._attempt_stable_reference(
                        source_entry, reference["reference"], target
                    )
                ):
                    return False
                selector_identities.append(
                    _repository_selector_identity(reference["reference"], target)
                )
                derived_edges.append(
                    {
                        "source_entry": copy.deepcopy(source_entry),
                        "reference": reference["reference"],
                        "target_entry": copy.deepcopy(target),
                    }
                )
            if len(selector_identities) != len(set(selector_identities)):
                return False
        derived_edges.sort(
            key=lambda edge: (
                *entry_key(edge["source_entry"]),
                edge["reference"],
                *entry_key(edge["target_entry"]),
            )
        )
        root_key = entry_key(workflow_entries[0])
        reachable = {root_key}
        while True:
            expanded = reachable | {
                entry_key(edge["target_entry"])
                for edge in derived_edges
                if entry_key(edge["source_entry"]) in reachable
            }
            if expanded == reachable:
                break
            reachable = expanded
        job_entry = producer["job_workflow_ref_identity"]["entry"]
        job_is_root = entry_key(job_entry) == root_key
        job_inbound_edges = [
            edge for edge in derived_edges if edge["target_entry"] == job_entry
        ]
        if (
            record_keys != sorted(entry_by_key)
            or len(record_keys) != len(set(record_keys))
            or edges != derived_edges
            or reachable != set(entry_by_key)
            or (job_is_root and job_inbound_edges)
            or (
                not job_is_root
                and (
                    len(job_inbound_edges) != 1
                    or not self._job_workflow_edge_matches(
                        job_inbound_edges[0], producer["job_workflow_ref"], job_entry
                    )
                )
            )
        ):
            return False

        inputs = operation["inputs"]
        if (
            not _same_repository(operation["repository"], contract["repository"])
            or operation["kind"]
            not in {
                "existing-run-rerun-failed-jobs",
                "existing-run-rerun-full",
            }
            or not self._positive_int(operation["workflow_id"])
            or not self._same_positive_int(
                operation["workflow_id"], producer["workflow_id"]
            )
            or not self._positive_int(operation["run_id"])
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
            or producer["feature_head_sha"] != contract["head_sha"]
        ):
            return False

        return (
            before["owner"] == "parent-orchestrator"
            and before["status"] == "complete"
            and before["profile"] == "github-codex-pre-mutation-run-observation-v1"
            and _same_repository(before["repository"], contract["repository"])
            and _repository_scoped_string_matches(
                before["query_endpoint"],
                "/repos/",
                contract["repository"],
                f"/actions/runs/{producer['run_id']}",
            )
            and before["api_version"] == "2026-03-10"
            and before["http_method"] == "GET"
            and before["response_status"] == 200
            and _timestamp(before["response_date"]) is not None
            and self._same_positive_int(before["run_id"], producer["run_id"])
            and self._same_positive_int(
                before["run_attempt"],
                producer["run_attempt"],
                operation["pre_run_attempt"],
            )
            and self._same_positive_int(
                operation["expected_run_attempt"], before["run_attempt"] + 1
            )
            and _timestamp(before["observed_at"]) is not None
            and before["head_sha"] == producer["feature_head_sha"]
            and self._same_positive_int(before["workflow_id"], producer["workflow_id"])
            and before["workflow_sha"] == producer["workflow_sha"]
            and _same_repository_selector(
                before["workflow_ref"],
                producer["workflow_ref"],
                (
                    f"/{producer['workflow_ref_identity']['path']}@"
                    f"{producer['workflow_ref_identity']['ref']}"
                ),
            )
            and before["run_ref"] == producer["run_ref"]
            and _same_repository_selector(
                before["job_workflow_ref"],
                producer["job_workflow_ref"],
                (
                    f"/{producer['job_workflow_ref_identity']['path']}@"
                    f"{producer['job_workflow_ref_identity']['ref']}"
                ),
            )
            and self._closed(before["platform_identity"], "platform_identity")
            and before["platform_identity"]["source"] == "github-actions-api"
            and before["platform_identity"]["authenticated"] is True
            and before["receipt_sha256"] == _receipt_sha256(before)
            and self._same_positive_int(operation["run_id"], producer["run_id"])
            and operation["ref"] == producer["run_ref"]
            and not inputs
        )

    def validate_completion(
        self, completion: object, accepted_preflight: dict[str, object]
    ) -> bool:
        try:
            return self._validate_completion(completion, accepted_preflight)
        except VALIDATION_EXCEPTIONS:
            return False

    def _validate_completion(
        self, completion: object, accepted_preflight: dict[str, object]
    ) -> bool:
        try:
            for value in (
                completion,
                accepted_preflight,
                self.platform_observation,
                self.post_current_observation,
                self.acquisition_transaction_receipt,
                self.dispatch_delivery_receipt,
            ):
                _require_rfc8785_integer_domain(value)
        except ValueError:
            return False
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
            or not _same_repository(
                delivery["repository"], accepted_preflight["repository"]
            )
            or delivery["api_version"] != "2026-03-10"
            or delivery["http_method"] != "POST"
            or not isinstance(delivery["request_server_time"], str)
            or not delivery["request_server_time"]
            or delivery["delivery_status"]
            not in {
                "existing-run-rerun-failed-jobs",
                "existing-run-rerun-full",
            }
            or not self._positive_int(delivery["returned_run_id"])
            or not self._positive_int(delivery["unique_run_id"])
            or not self._same_positive_int(
                delivery["unique_run_id"], delivery["returned_run_id"]
            )
            or delivery["receipt_sha256"] != _receipt_sha256(delivery)
            or delivery["receipt_sha256"] != self.expected_delivery_receipt_sha256
            or not self._closed(
                observation, "platform_dispatch_run_observation_receipt"
            )
            or observation["owner"] != "parent-orchestrator"
            or observation["status"] != "complete"
            or observation["profile"]
            != "github-codex-platform-dispatch-run-observation-v1"
            or not _same_repository(
                observation["query_repository"], accepted_preflight["repository"]
            )
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
            or not self._same_positive_int(
                observation["returned_run_id"], delivery["returned_run_id"]
            )
            or not self._closed(run_object, "platform_run_object")
            or not self._positive_int(run_object["id"])
            or not self._positive_int(run_object["run_attempt"])
            or not self._positive_int(run_object["workflow_id"])
            or not self._same_positive_int(
                run_object["id"], observation["returned_run_id"]
            )
            or observation["run_object_sha256"] != _canonical_sha256(run_object)
            or not self._closed(observation["platform_identity"], "platform_identity")
            or observation["platform_identity"]["source"] != "github-actions-api"
            or observation["platform_identity"]["authenticated"] is not True
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
            or not _same_repository(
                current_observation["query_repository"],
                accepted_preflight["repository"],
            )
            or not _repository_scoped_string_matches(
                current_observation["query_endpoint"],
                "/repos/",
                accepted_preflight["repository"],
                f"/actions/runs/{observation['returned_run_id']}",
            )
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
            or not self._same_positive_int(
                current_observation["returned_run_id"], observation["returned_run_id"]
            )
            or not self._closed(current_run_object, "platform_run_object")
            or not self._positive_int(current_run_object["id"])
            or not self._positive_int(current_run_object["run_attempt"])
            or not self._positive_int(current_run_object["workflow_id"])
            or not self._same_positive_int(
                current_run_object["id"], observation["returned_run_id"]
            )
            or current_observation["run_object_sha256"]
            != _canonical_sha256(current_run_object)
            or not self._closed(
                current_observation["platform_identity"], "platform_identity"
            )
            or current_observation["platform_identity"]["source"]
            != "github-actions-api"
            or current_observation["platform_identity"]["authenticated"] is not True
            or current_observation["receipt_sha256"]
            != _receipt_sha256(current_observation)
        ):
            return False
        frozen_identity_fields = (
            "id",
            "run_attempt",
            "head_sha",
            "workflow_id",
            "workflow_sha",
            "run_ref",
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
            or not _same_repository(
                current_run_object["repository"], run_object["repository"]
            )
            or not _same_repository_selector(
                current_run_object["workflow_ref"],
                run_object["workflow_ref"],
                (
                    f"/{producer['workflow_ref_identity']['path']}@"
                    f"{producer['workflow_ref_identity']['ref']}"
                ),
            )
            or not _same_repository_selector(
                current_run_object["job_workflow_ref"],
                run_object["job_workflow_ref"],
                (
                    f"/{producer['job_workflow_ref_identity']['path']}@"
                    f"{producer['job_workflow_ref_identity']['ref']}"
                ),
            )
            or not _repository_scoped_string_matches(
                current_run_object["previous_attempt_url"],
                "https://api.github.com/repos/",
                accepted_preflight["repository"],
                (
                    f"/actions/runs/{producer['run_id']}/attempts/"
                    f"{producer['run_attempt']}"
                ),
            )
            or not _repository_scoped_string_matches(
                run_object["previous_attempt_url"],
                "https://api.github.com/repos/",
                accepted_preflight["repository"],
                (
                    f"/actions/runs/{producer['run_id']}/attempts/"
                    f"{producer['run_attempt']}"
                ),
            )
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
            or not _same_repository(
                transaction["repository"], accepted_preflight["repository"]
            )
            or not self._positive_int(transaction["run_id"])
            or not self._same_positive_int(
                transaction["run_id"], observation["returned_run_id"]
            )
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
            or not _repository_scoped_string_matches(
                delivery["request_endpoint"],
                "/repos/",
                accepted_preflight["repository"],
                f"/actions/runs/{expected_run_id}/{endpoint_suffix}",
            )
            or delivery["request_body"] is not None
            or delivery["request_body_encoding"] != "absent-v1"
            or delivery["request_body_sha256"] != _canonical_sha256(None)
            or delivery["response_status"] != 201
            or delivery["response"] is not None
            or delivery["response_sha256"] is not None
            or not self._positive_int(producer_attempt)
            or not self._positive_int(run_object["run_attempt"])
            or not self._same_positive_int(
                run_object["run_attempt"],
                producer_attempt + 1,
                operation["expected_run_attempt"],
            )
            or not _repository_scoped_string_matches(
                observation["query_endpoint"],
                "/repos/",
                accepted_preflight["repository"],
                (f"/actions/runs/{expected_run_id}/attempts/{producer_attempt + 1}"),
            )
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
            or not _repository_scoped_string_matches(
                run_object["previous_attempt_url"],
                "https://api.github.com/repos/",
                accepted_preflight["repository"],
                f"/actions/runs/{expected_run_id}/attempts/{producer_attempt}",
            )
            or not self._same_positive_int(
                current_run_object["run_attempt"], producer_attempt + 1
            )
            or not _repository_scoped_string_matches(
                current_run_object["previous_attempt_url"],
                "https://api.github.com/repos/",
                accepted_preflight["repository"],
                f"/actions/runs/{expected_run_id}/attempts/{producer_attempt}",
            )
            or {
                key: current_run_object[key]
                for key in (
                    "id",
                    "run_attempt",
                    "head_sha",
                    "workflow_id",
                    "workflow_sha",
                    "run_ref",
                )
            }
            != {
                key: run_object[key]
                for key in (
                    "id",
                    "run_attempt",
                    "head_sha",
                    "workflow_id",
                    "workflow_sha",
                    "run_ref",
                )
            }
            or not _same_repository(
                current_run_object["repository"], run_object["repository"]
            )
            or not _same_repository_selector(
                current_run_object["workflow_ref"],
                run_object["workflow_ref"],
                (
                    f"/{producer['workflow_ref_identity']['path']}@"
                    f"{producer['workflow_ref_identity']['ref']}"
                ),
            )
            or not _same_repository_selector(
                current_run_object["job_workflow_ref"],
                run_object["job_workflow_ref"],
                (
                    f"/{producer['job_workflow_ref_identity']['path']}@"
                    f"{producer['job_workflow_ref_identity']['ref']}"
                ),
            )
            or not self._closed(transaction, "recovery_acquisition_transaction_receipt")
            or transaction["owner"] != "parent-orchestrator"
            or transaction["status"] != "complete"
            or transaction["profile"]
            != "github-codex-recovery-acquisition-transaction-v1"
            or not _same_repository(
                transaction["repository"], accepted_preflight["repository"]
            )
            or not self._same_positive_int(transaction["run_id"], expected_run_id)
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
            and self._same_positive_int(
                completion["returned_run_id"],
                expected_run_id,
                observation["returned_run_id"],
            )
            and _same_repository(
                completion["observed_repository"], run_object["repository"]
            )
            and _same_repository(
                run_object["repository"], accepted_preflight["repository"]
            )
            and self._same_positive_int(
                completion["observed_run_attempt"], run_object["run_attempt"]
            )
            and completion["observed_head_sha"]
            == run_object["head_sha"]
            == accepted_preflight["head_sha"]
            and self._same_positive_int(
                completion["observed_workflow_id"],
                run_object["workflow_id"],
                operation["workflow_id"],
            )
            and completion["observed_workflow_sha"]
            == run_object["workflow_sha"]
            == producer["workflow_sha"]
            and _same_repository_selector(
                completion["observed_workflow_ref"],
                run_object["workflow_ref"],
                (
                    f"/{producer['workflow_ref_identity']['path']}@"
                    f"{producer['workflow_ref_identity']['ref']}"
                ),
            )
            and _same_repository_selector(
                run_object["workflow_ref"],
                producer["workflow_ref"],
                (
                    f"/{producer['workflow_ref_identity']['path']}@"
                    f"{producer['workflow_ref_identity']['ref']}"
                ),
            )
            and completion["observed_run_ref"]
            == run_object["run_ref"]
            == operation["ref"]
            and _same_repository_selector(
                completion["observed_job_workflow_ref"],
                run_object["job_workflow_ref"],
                (
                    f"/{producer['job_workflow_ref_identity']['path']}@"
                    f"{producer['job_workflow_ref_identity']['ref']}"
                ),
            )
            and _same_repository_selector(
                run_object["job_workflow_ref"],
                producer["job_workflow_ref"],
                (
                    f"/{producer['job_workflow_ref_identity']['path']}@"
                    f"{producer['job_workflow_ref_identity']['ref']}"
                ),
            )
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
                "repository": "octo/review-fixture",
                "commit": "2" * 40,
                "path": ".github/workflows/recovery.yml",
                "blob_sha256": "7" * 64,
                "kind": "workflow",
            },
            {
                "repository": "octo/z-recovery-policy",
                "commit": "2" * 40,
                "path": ".github/workflows/reconcile.yml",
                "blob_sha256": "8" * 64,
                "kind": "reusable-workflow",
            },
            {
                "repository": "octo/z-recovery-policy",
                "commit": "2" * 40,
                "path": "actions/verify/action.yml",
                "blob_sha256": "9" * 64,
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
            "workflow_repository": "octo/review-fixture",
            "workflow_path": ".github/workflows/recovery.yml",
            "workflow_sha": "2" * 40,
            "workflow_ref": (
                "octo/review-fixture/.github/workflows/recovery.yml@refs/heads/feature/review"
            ),
            "workflow_ref_identity": {
                "repository": "octo/review-fixture",
                "path": ".github/workflows/recovery.yml",
                "ref": "refs/heads/feature/review",
                "resolved_commit": "2" * 40,
                "entry": copy.deepcopy(producer_closure[0]),
                "entry_sha256": _canonical_sha256(producer_closure[0]),
            },
            "job_workflow_ref": (
                "octo/z-recovery-policy/.github/workflows/reconcile.yml@" + "2" * 40
            ),
            "job_workflow_ref_identity": {
                "repository": "octo/z-recovery-policy",
                "path": ".github/workflows/reconcile.yml",
                "ref": "2" * 40,
                "resolved_commit": "2" * 40,
                "entry": copy.deepcopy(producer_closure[1]),
                "entry_sha256": _canonical_sha256(producer_closure[1]),
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
                    "reference": (
                        "octo/z-recovery-policy/.github/workflows/reconcile.yml"
                        "@" + "2" * 40
                    ),
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
            "discovered_references": [
                {
                    "reference": ("octo/z-recovery-policy/actions/verify@" + "2" * 40),
                    "target_entry": copy.deepcopy(producer_closure[2]),
                }
            ],
            "discovered_reference_count": 1,
            "record_sha256": "",
        }
        action_record["record_sha256"] = _canonical_sha256(
            {k: v for k, v in action_record.items() if k != "record_sha256"}
        )
        transitive_action_record = {
            "source_entry": copy.deepcopy(producer_closure[2]),
            "parser_profile": "github-actions-dependency-resolver-v1",
            "source_sha256": producer_closure[2]["blob_sha256"],
            "discovered_references": [],
            "discovered_reference_count": 0,
            "record_sha256": "",
        }
        transitive_action_record["record_sha256"] = _canonical_sha256(
            {k: v for k, v in transitive_action_record.items() if k != "record_sha256"}
        )
        resolution_records = sorted(
            [
                resolution_record,
                action_record,
                transitive_action_record,
            ],
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
                "reference": (
                    "octo/z-recovery-policy/.github/workflows/reconcile.yml@" + "2" * 40
                ),
                "target_entry": copy.deepcopy(producer_closure[1]),
            },
            {
                "source_entry": copy.deepcopy(producer_closure[1]),
                "reference": ("octo/z-recovery-policy/actions/verify@" + "2" * 40),
                "target_entry": copy.deepcopy(producer_closure[2]),
            },
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
            "record_count": 3,
            "records_sha256": _canonical_sha256(resolution_records),
            "edges": resolution_edges,
            "edge_count": 2,
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
        self.assertIn(
            "canonical repository/workflow-path@full-commit",
            self.recovery_schema["rules"]["attempt_stable_dependencies"],
        )
        self.assertIn(
            "conservative rule applies to both full and failed-jobs reruns",
            self.recovery_schema["rules"]["attempt_stable_dependencies"],
        )
        self.assertIn(
            "runtime resolution bases",
            self.recovery_schema["rules"]["attempt_stable_dependencies"],
        )
        self.assertIn(
            "exactly one total inbound edge",
            self.recovery_schema["rules"]["attempt_stable_dependencies"],
        )
        self.assertIn(
            "complete dependency graph to be attempt-stable",
            " ".join(self.authority.split()),
        )
        self.assertIn(
            "complete dependency graph attempt-stable",
            " ".join(self.probes.split()),
        )
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

        manual_dispatch = copy.deepcopy(self.recovery_contract)
        manual_dispatch["operation_intent"].update(
            kind="manual-workflow-dispatch",
            run_id=None,
            pre_run_attempt=None,
            expected_run_attempt=None,
        )
        manual_dispatch["repeat_safety"]["operation_identity_sha256"] = (
            _canonical_sha256(manual_dispatch["operation_intent"])
        )
        manual_dispatch["preflight_sha256"] = _canonical_sha256(
            {
                key: value
                for key, value in manual_dispatch.items()
                if key != "preflight_sha256"
            }
        )
        self.assertFalse(self.recovery_validator.validate_preflight(manual_dispatch))

    def test_recovery_source_trust_anchor_kind_relationships_are_closed(
        self,
    ) -> None:
        producer_fields = self.carriers["required_report_schema"][
            "parent_input_profiles"
        ]["merge_status_producer_implementation_receipt"]

        def rehash_contract(contract: dict[str, object]) -> None:
            source = contract["source_descriptor"]
            anchor = contract["source_trust_anchor"]
            anchor["identity"] = (
                f"{source['source_repository']}@{source['source_commit']}:"
                f"{source['source_path']}"
            )
            anchor["sha256"] = source["source_sha256"]

            exclusion = contract["candidate_range_exclusion_receipt"]
            exclusion["source"] = copy.deepcopy(source)
            exclusion["candidate_commit_count"] = len(exclusion["candidate_commits"])
            exclusion["candidate_commits_sha256"] = _commit_set_sha256(
                exclusion["candidate_commits"]
            )

            resolution = contract["dependency_edge_resolution_receipt"]
            resolver = resolution["resolver_anchor"]
            resolver["candidate_range_exclusion_sha256"] = _canonical_sha256(exclusion)
            resolver["receipt_sha256"] = _receipt_sha256(resolver)
            resolution["receipt_sha256"] = _receipt_sha256(resolution)
            contract["preflight_sha256"] = _canonical_sha256(
                {
                    key: value
                    for key, value in contract.items()
                    if key != "preflight_sha256"
                }
            )

        def validator_for(
            contract: dict[str, object],
        ) -> _RecoveryContractValidator:
            resolution = contract["dependency_edge_resolution_receipt"]
            return _RecoveryContractValidator(
                self.recovery_schema,
                self.producer_receipt,
                producer_fields,
                self.platform_observation,
                self.dispatch_delivery_receipt,
                self.dispatch_delivery_receipt["receipt_sha256"],
                resolution,
                resolution["resolver_anchor"],
                contract["pre_mutation_run_observation"],
                self.post_current_observation,
                self.acquisition_transaction,
            )

        valid_relationships = {
            "target-baseline-case-alias": (
                "target-branch-baseline",
                self.recovery_contract["repository"].upper(),
                self.recovery_contract["source_trust_anchor"]["base_sha"],
            ),
            "installed-prior-candidate-repository-release": (
                "installed-trusted-release",
                self.recovery_contract["repository"],
                self.recovery_contract["source_trust_anchor"]["base_sha"],
            ),
            "parent-fixed-external": (
                "parent-fixed-external",
                self.recovery_contract["source_descriptor"]["source_repository"],
                self.recovery_contract["source_descriptor"]["source_commit"],
            ),
        }
        for name, (kind, repository, commit) in valid_relationships.items():
            with self.subTest(valid_source_relationship=name):
                contract = copy.deepcopy(self.recovery_contract)
                contract["source_trust_anchor"]["kind"] = kind
                contract["source_descriptor"].update(
                    source_repository=repository,
                    source_commit=commit,
                )
                rehash_contract(contract)
                self.assertTrue(validator_for(contract).validate_preflight(contract))

        invalid_relationships = {
            "baseline-from-different-repository": (
                "target-branch-baseline",
                self.recovery_contract["source_descriptor"]["source_repository"],
                self.recovery_contract["source_trust_anchor"]["base_sha"],
            ),
            "baseline-from-wrong-candidate-commit": (
                "target-branch-baseline",
                self.recovery_contract["repository"],
                "e" * 40,
            ),
            "external-from-candidate-repository-case-alias": (
                "parent-fixed-external",
                self.recovery_contract["repository"].upper(),
                self.recovery_contract["source_trust_anchor"]["base_sha"],
            ),
            "installed-release-from-candidate-range": (
                "installed-trusted-release",
                self.recovery_contract["repository"].upper(),
                "d" * 40,
            ),
        }
        for name, (kind, repository, commit) in invalid_relationships.items():
            with self.subTest(invalid_source_relationship=name):
                contract = copy.deepcopy(self.recovery_contract)
                contract["source_trust_anchor"]["kind"] = kind
                contract["source_descriptor"].update(
                    source_repository=repository,
                    source_commit=commit,
                )
                rehash_contract(contract)
                self.assertFalse(validator_for(contract).validate_preflight(contract))

    def test_recovery_requires_attempt_stable_dependency_references(self) -> None:
        self.assertTrue(
            self.recovery_validator.validate_preflight(self.recovery_contract)
        )

        source_workflow = copy.deepcopy(
            self.producer_receipt["implementation_closure"][1]
        )
        target_action = copy.deepcopy(
            self.producer_receipt["implementation_closure"][2]
        )
        self.assertTrue(
            self.recovery_validator._attempt_stable_reference(
                source_workflow,
                "octo/z-recovery-policy/actions/verify@" + "2" * 40,
                target_action,
            )
        )
        for reference in (
            "./actions/verify",
            "../actions/verify",
            "octo/z-recovery-policy/actions/verify/action.yml@" + "2" * 40,
            "octo/z-recovery-policy/actions/verify@" + "3" * 40,
        ):
            with self.subTest(reference=reference):
                self.assertFalse(
                    self.recovery_validator._attempt_stable_reference(
                        source_workflow, reference, target_action
                    )
                )
        self.assertTrue(
            self.recovery_validator._attempt_stable_reference(
                source_workflow, "$/actions/verify", target_action
            )
        )
        self.assertFalse(
            self.recovery_validator._attempt_stable_reference(
                source_workflow,
                "$/actions/verify@" + "2" * 40,
                target_action,
            )
        )
        root_action = copy.deepcopy(target_action)
        root_action["path"] = "action.yaml"
        self.assertTrue(
            self.recovery_validator._attempt_stable_reference(
                source_workflow,
                "octo/z-recovery-policy@" + "2" * 40,
                root_action,
            )
        )
        invalid_action = copy.deepcopy(target_action)
        invalid_action["path"] = "actions/verify/manifest.yml"
        self.assertFalse(
            self.recovery_validator._attempt_stable_reference(
                source_workflow,
                "octo/z-recovery-policy/actions/verify@" + "2" * 40,
                invalid_action,
            )
        )

        for suffix in ("yml", "yaml"):
            local_workflow = {
                "repository": source_workflow["repository"],
                "commit": source_workflow["commit"],
                "path": f".github/workflows/local.{suffix}",
                "blob_sha256": "b" * 64,
                "kind": "reusable-workflow",
            }
            for prefix in ("./", "$/"):
                reference = f"{prefix}{local_workflow['path']}"
                with self.subTest(reference=reference):
                    self.assertTrue(
                        self.recovery_validator._attempt_stable_reference(
                            source_workflow, reference, local_workflow
                        )
                    )
        local_workflow = {
            "repository": source_workflow["repository"],
            "commit": source_workflow["commit"],
            "path": ".github/workflows/local.yml",
            "blob_sha256": "b" * 64,
            "kind": "reusable-workflow",
        }
        for field, value in (
            ("repository", "octo/different"),
            ("commit", "3" * 40),
            ("path", ".github/workflows/different.yml"),
        ):
            with self.subTest(local_workflow_mismatch=field):
                mismatched = copy.deepcopy(local_workflow)
                mismatched[field] = value
                self.assertFalse(
                    self.recovery_validator._attempt_stable_reference(
                        source_workflow,
                        "./.github/workflows/local.yml",
                        mismatched,
                    )
                )
        for bad_path in (
            "scripts/not-a-workflow.yml",
            ".github/workflows/nested/workflow.yml",
            ".github/workflows/not-a-workflow.txt",
        ):
            bad_workflow = copy.deepcopy(local_workflow)
            bad_workflow["path"] = bad_path
            for reference in (
                f"{bad_workflow['repository']}/{bad_path}@{bad_workflow['commit']}",
                f"./{bad_path}",
                f"$/{bad_path}",
            ):
                with self.subTest(bad_reusable_path=bad_path, reference=reference):
                    self.assertFalse(
                        self.recovery_validator._attempt_stable_reference(
                            source_workflow, reference, bad_workflow
                        )
                    )
        target_script = {
            "repository": target_action["repository"],
            "commit": target_action["commit"],
            "path": "scripts/verify.sh",
            "blob_sha256": "c" * 64,
            "kind": "script",
        }
        self.assertFalse(
            self.recovery_validator._attempt_stable_reference(
                target_action, "../../scripts/verify.sh", target_script
            )
        )

        def local_reusable_validator(
            reference_prefix: str,
            *,
            job_commit: str = "2" * 40,
            job_path: str = ".github/workflows/reconcile.yml",
            duplicate_inbound: bool = False,
        ) -> tuple[_RecoveryContractValidator, dict[str, object]]:
            producer = copy.deepcopy(self.producer_receipt)
            contract = copy.deepcopy(self.recovery_contract)
            root_entry = copy.deepcopy(producer["workflow_ref_identity"]["entry"])
            old_job_entry = copy.deepcopy(
                producer["job_workflow_ref_identity"]["entry"]
            )
            local_job_entry = copy.deepcopy(old_job_entry)
            local_job_entry.update(
                repository=root_entry["repository"],
                commit=job_commit,
                path=job_path,
            )
            producer["implementation_closure"] = [
                (
                    copy.deepcopy(local_job_entry)
                    if entry == old_job_entry
                    else copy.deepcopy(entry)
                )
                for entry in producer["implementation_closure"]
            ]
            producer["implementation_closure"].sort(
                key=lambda entry: (
                    entry["repository"],
                    entry["commit"],
                    entry["path"],
                    entry["kind"],
                    entry["blob_sha256"],
                )
            )
            producer["job_workflow_ref_identity"].update(
                repository=local_job_entry["repository"],
                path=local_job_entry["path"],
                ref=producer["run_ref"],
                resolved_commit=local_job_entry["commit"],
                entry=copy.deepcopy(local_job_entry),
                entry_sha256=_canonical_sha256(local_job_entry),
            )
            producer["job_workflow_ref"] = (
                f"{local_job_entry['repository']}/{local_job_entry['path']}@"
                f"{producer['run_ref']}"
            )
            producer["implementation_closure_sha256"] = _canonical_sha256(
                producer["implementation_closure"]
            )
            producer["receipt_sha256"] = _receipt_sha256(producer)
            contract["implementation_receipt_identity"]["receipt_sha256"] = producer[
                "receipt_sha256"
            ]

            resolution = contract["dependency_edge_resolution_receipt"]
            local_reference = f"{reference_prefix}.github/workflows/reconcile.yml"
            for record in resolution["records"]:
                if record["source_entry"] == old_job_entry:
                    record["source_entry"] = copy.deepcopy(local_job_entry)
                    record["source_sha256"] = local_job_entry["blob_sha256"]
                for dependency in record["discovered_references"]:
                    if dependency["target_entry"] == old_job_entry:
                        dependency["target_entry"] = copy.deepcopy(local_job_entry)
                        dependency["reference"] = local_reference
                record["record_sha256"] = _canonical_sha256(
                    {
                        key: value
                        for key, value in record.items()
                        if key != "record_sha256"
                    }
                )
            if duplicate_inbound:
                job_record = next(
                    record
                    for record in resolution["records"]
                    if record["source_entry"] == local_job_entry
                )
                job_record["discovered_references"].append(
                    {
                        "reference": f"$/{local_job_entry['path']}",
                        "target_entry": copy.deepcopy(local_job_entry),
                    }
                )
                job_record["discovered_references"].sort(
                    key=lambda item: (
                        item["reference"],
                        item["target_entry"]["repository"],
                        item["target_entry"]["commit"],
                        item["target_entry"]["path"],
                        item["target_entry"]["kind"],
                        item["target_entry"]["blob_sha256"],
                    )
                )
                job_record["discovered_reference_count"] = len(
                    job_record["discovered_references"]
                )
                job_record["record_sha256"] = _canonical_sha256(
                    {
                        key: value
                        for key, value in job_record.items()
                        if key != "record_sha256"
                    }
                )
            resolution["records"].sort(
                key=lambda record: (
                    record["source_entry"]["repository"],
                    record["source_entry"]["commit"],
                    record["source_entry"]["path"],
                    record["source_entry"]["kind"],
                    record["source_entry"]["blob_sha256"],
                )
            )
            resolution["implementation_receipt_sha256"] = producer["receipt_sha256"]
            resolution["records_sha256"] = _canonical_sha256(resolution["records"])
            for edge in resolution["edges"]:
                if edge["source_entry"] == old_job_entry:
                    edge["source_entry"] = copy.deepcopy(local_job_entry)
                if edge["target_entry"] == old_job_entry:
                    edge["target_entry"] = copy.deepcopy(local_job_entry)
                    edge["reference"] = local_reference
            if duplicate_inbound:
                resolution["edges"].append(
                    {
                        "source_entry": copy.deepcopy(local_job_entry),
                        "reference": f"$/{local_job_entry['path']}",
                        "target_entry": copy.deepcopy(local_job_entry),
                    }
                )
            resolution["edges"].sort(
                key=lambda edge: (
                    edge["source_entry"]["repository"],
                    edge["source_entry"]["commit"],
                    edge["source_entry"]["path"],
                    edge["source_entry"]["kind"],
                    edge["source_entry"]["blob_sha256"],
                    edge["reference"],
                    edge["target_entry"]["repository"],
                    edge["target_entry"]["commit"],
                    edge["target_entry"]["path"],
                    edge["target_entry"]["kind"],
                    edge["target_entry"]["blob_sha256"],
                )
            )
            resolution["edges_sha256"] = _canonical_sha256(resolution["edges"])
            resolution["receipt_sha256"] = _receipt_sha256(resolution)
            before = contract["pre_mutation_run_observation"]
            before["job_workflow_ref"] = producer["job_workflow_ref"]
            before["receipt_sha256"] = _receipt_sha256(before)
            contract["preflight_sha256"] = _canonical_sha256(
                {
                    key: value
                    for key, value in contract.items()
                    if key != "preflight_sha256"
                }
            )
            validator = _RecoveryContractValidator(
                self.recovery_schema,
                producer,
                self.carriers["required_report_schema"]["parent_input_profiles"][
                    "merge_status_producer_implementation_receipt"
                ],
                self.platform_observation,
                self.dispatch_delivery_receipt,
                self.dispatch_delivery_receipt["receipt_sha256"],
                resolution,
                resolution["resolver_anchor"],
                before,
                self.post_current_observation,
                self.acquisition_transaction,
            )
            return validator, contract

        for reference_prefix in ("./", "$/"):
            with self.subTest(local_reusable_full_contract=reference_prefix):
                validator, contract = local_reusable_validator(reference_prefix)
                self.assertTrue(validator.validate_preflight(contract))
        for mismatch, kwargs in (
            ("commit", {"job_commit": "3" * 40}),
            ("path", {"job_path": ".github/workflows/different.yml"}),
        ):
            with self.subTest(local_reusable_full_contract_mismatch=mismatch):
                validator, contract = local_reusable_validator("./", **kwargs)
                self.assertFalse(validator.validate_preflight(contract))
        duplicate_validator, duplicate_contract = local_reusable_validator(
            "./", duplicate_inbound=True
        )
        self.assertFalse(duplicate_validator.validate_preflight(duplicate_contract))

        for operation_kind in (
            "existing-run-rerun-full",
            "existing-run-rerun-failed-jobs",
        ):
            for resolved_ref in (
                "refs/heads/feature/review",
                "v2",
                "${{ github.ref }}",
                "3" * 40,
            ):
                with self.subTest(
                    operation_kind=operation_kind, resolved_ref=resolved_ref
                ):
                    producer = copy.deepcopy(self.producer_receipt)
                    contract = copy.deepcopy(self.recovery_contract)
                    contract["operation_intent"]["kind"] = operation_kind
                    identity = producer["job_workflow_ref_identity"]
                    identity["ref"] = resolved_ref
                    producer["job_workflow_ref"] = (
                        f"{identity['repository']}/{identity['path']}@{resolved_ref}"
                    )
                    producer["receipt_sha256"] = _receipt_sha256(producer)
                    contract["implementation_receipt_identity"]["receipt_sha256"] = (
                        producer["receipt_sha256"]
                    )

                    resolution = contract["dependency_edge_resolution_receipt"]
                    resolution["implementation_receipt_sha256"] = producer[
                        "receipt_sha256"
                    ]
                    external_reference = producer["job_workflow_ref"]
                    resolution["records"][0]["discovered_references"][0][
                        "reference"
                    ] = external_reference
                    resolution["records"][0]["record_sha256"] = _canonical_sha256(
                        {
                            key: value
                            for key, value in resolution["records"][0].items()
                            if key != "record_sha256"
                        }
                    )
                    resolution["records_sha256"] = _canonical_sha256(
                        resolution["records"]
                    )
                    resolution["edges"][0]["reference"] = external_reference
                    resolution["edges_sha256"] = _canonical_sha256(resolution["edges"])
                    resolution["receipt_sha256"] = _receipt_sha256(resolution)

                    before = contract["pre_mutation_run_observation"]
                    before["job_workflow_ref"] = external_reference
                    before["receipt_sha256"] = _receipt_sha256(before)
                    contract["repeat_safety"]["operation_identity_sha256"] = (
                        _canonical_sha256(contract["operation_intent"])
                    )
                    contract["preflight_sha256"] = _canonical_sha256(
                        {
                            key: value
                            for key, value in contract.items()
                            if key != "preflight_sha256"
                        }
                    )
                    validator = _RecoveryContractValidator(
                        self.recovery_schema,
                        producer,
                        self.carriers["required_report_schema"][
                            "parent_input_profiles"
                        ]["merge_status_producer_implementation_receipt"],
                        self.platform_observation,
                        self.dispatch_delivery_receipt,
                        self.dispatch_delivery_receipt["receipt_sha256"],
                        resolution,
                        resolution["resolver_anchor"],
                        before,
                        self.post_current_observation,
                        self.acquisition_transaction,
                    )
                    self.assertFalse(validator.validate_preflight(contract))

        for operation_kind in (
            "existing-run-rerun-full",
            "existing-run-rerun-failed-jobs",
        ):
            with self.subTest(operation_kind=operation_kind, mismatch="job-edge"):
                producer = copy.deepcopy(self.producer_receipt)
                contract = copy.deepcopy(self.recovery_contract)
                contract["operation_intent"]["kind"] = operation_kind
                identity = producer["job_workflow_ref_identity"]
                identity["ref"] = "refs/heads/main"
                producer["job_workflow_ref"] = (
                    f"{identity['repository']}/{identity['path']}@{identity['ref']}"
                )
                producer["receipt_sha256"] = _receipt_sha256(producer)
                contract["implementation_receipt_identity"]["receipt_sha256"] = (
                    producer["receipt_sha256"]
                )
                resolution = contract["dependency_edge_resolution_receipt"]
                resolution["implementation_receipt_sha256"] = producer["receipt_sha256"]
                resolution["receipt_sha256"] = _receipt_sha256(resolution)
                before = contract["pre_mutation_run_observation"]
                before["job_workflow_ref"] = producer["job_workflow_ref"]
                before["receipt_sha256"] = _receipt_sha256(before)
                contract["repeat_safety"]["operation_identity_sha256"] = (
                    _canonical_sha256(contract["operation_intent"])
                )
                contract["preflight_sha256"] = _canonical_sha256(
                    {
                        key: value
                        for key, value in contract.items()
                        if key != "preflight_sha256"
                    }
                )
                validator = _RecoveryContractValidator(
                    self.recovery_schema,
                    producer,
                    self.carriers["required_report_schema"]["parent_input_profiles"][
                        "merge_status_producer_implementation_receipt"
                    ],
                    self.platform_observation,
                    self.dispatch_delivery_receipt,
                    self.dispatch_delivery_receipt["receipt_sha256"],
                    resolution,
                    resolution["resolver_anchor"],
                    before,
                    self.post_current_observation,
                    self.acquisition_transaction,
                )
                self.assertFalse(validator.validate_preflight(contract))

    def test_recovery_rfc8785_inputs_use_the_safe_integer_domain(self) -> None:
        self.assertEqual(
            _repository_identity("OcTo/Review-Fixture"),
            "octo/review-fixture",
        )
        for malformed_repository in (
            "Öcto/review-fixture",
            "octo/仓库",
            "owner/",
            "/repo",
            "owner/..",
            "owner/re po",
            "owner/repo?",
            "owner/repo#",
            "owner/repo@",
            "owner/repo%",
            "owner/repo\\name",
            f"owner/{'a' * 101}",
        ):
            with self.subTest(malformed_repository=malformed_repository):
                self.assertIsNone(_repository_identity(malformed_repository))

        self.assertEqual(
            _canonical_sha256({"id": MAX_SAFE_INTEGER}),
            hashlib.sha256(f'{{"id":{MAX_SAFE_INTEGER}}}'.encode()).hexdigest(),
        )
        for value in (
            MAX_SAFE_INTEGER + 1,
            -(MAX_SAFE_INTEGER + 1),
            {"nested": [9_007_199_254_740_993]},
            {"non-ascii-key-\N{SNOWMAN}": 1},
            "\ud800",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                _canonical_sha256(value)

        cyclic: list[object] = []
        cyclic.append(cyclic)
        with self.assertRaises(ValueError):
            _canonical_sha256(cyclic)

        def nested_lists(depth: int) -> list[object]:
            root: list[object] = []
            cursor = root
            for _ in range(depth - 1):
                child: list[object] = []
                cursor.append(child)
                cursor = child
            return root

        at_depth_limit = nested_lists(MAX_CANONICAL_JSON_DEPTH)
        _canonical_sha256(at_depth_limit)
        deep = nested_lists(MAX_CANONICAL_JSON_DEPTH + 1)
        with self.assertRaises(ValueError):
            _canonical_sha256(deep)

        at_node_limit = [None] * (MAX_CANONICAL_JSON_NODES - 1)
        _require_rfc8785_integer_domain(at_node_limit)
        over_node_limit = [None] * MAX_CANONICAL_JSON_NODES
        with self.assertRaises(ValueError):
            _require_rfc8785_integer_domain(over_node_limit)
        overwide_object = {
            f"key-{index}": None for index in range(MAX_CANONICAL_JSON_NODES)
        }
        with self.assertRaises(ValueError):
            _require_rfc8785_integer_domain(overwide_object)

        boundary_string = "a" * MAX_CANONICAL_JSON_STRING_UTF8_BYTES
        _require_rfc8785_integer_domain(boundary_string)
        with self.assertRaises(ValueError):
            _require_rfc8785_integer_domain(boundary_string + "a")
        aggregate_chunks = (
            MAX_CANONICAL_JSON_AGGREGATE_UTF8_BYTES
            // MAX_CANONICAL_JSON_STRING_UTF8_BYTES
        )
        aggregate_boundary = [boundary_string] * (aggregate_chunks - 1) + [
            {boundary_string: None}
        ]
        _require_rfc8785_integer_domain(aggregate_boundary)
        with self.assertRaises(ValueError):
            _require_rfc8785_integer_domain([*aggregate_boundary, "a"])

        constructor_validator = _RecoveryContractValidator(
            self.recovery_schema,
            deep,
            self.carriers["required_report_schema"]["parent_input_profiles"][
                "merge_status_producer_implementation_receipt"
            ],
            self.platform_observation,
            self.dispatch_delivery_receipt,
            self.dispatch_delivery_receipt["receipt_sha256"],
            self.recovery_contract["dependency_edge_resolution_receipt"],
            self.recovery_contract["dependency_edge_resolution_receipt"][
                "resolver_anchor"
            ],
            self.recovery_contract["pre_mutation_run_observation"],
            self.post_current_observation,
            self.acquisition_transaction,
        )
        self.assertFalse(
            constructor_validator.validate_preflight(self.recovery_contract)
        )
        oversized_constructor_validator = _RecoveryContractValidator(
            self.recovery_schema,
            boundary_string + "a",
            self.carriers["required_report_schema"]["parent_input_profiles"][
                "merge_status_producer_implementation_receipt"
            ],
            self.platform_observation,
            self.dispatch_delivery_receipt,
            self.dispatch_delivery_receipt["receipt_sha256"],
            self.recovery_contract["dependency_edge_resolution_receipt"],
            self.recovery_contract["dependency_edge_resolution_receipt"][
                "resolver_anchor"
            ],
            self.recovery_contract["pre_mutation_run_observation"],
            self.post_current_observation,
            self.acquisition_transaction,
        )
        self.assertFalse(
            oversized_constructor_validator.validate_preflight(self.recovery_contract)
        )

        unsafe_contract = copy.deepcopy(self.recovery_contract)
        unsafe_contract["operation_intent"]["run_id"] = 9_007_199_254_740_993
        self.assertFalse(self.recovery_validator.validate_preflight(unsafe_contract))

        surrogate_contract = copy.deepcopy(self.recovery_contract)
        surrogate_contract["operation_intent"]["kind"] = "\ud800"
        self.assertFalse(self.recovery_validator.validate_preflight(surrogate_contract))
        malformed_shape = copy.deepcopy(self.recovery_contract)
        malformed_shape["operation_intent"]["kind"] = []
        self.assertFalse(self.recovery_validator.validate_preflight(malformed_shape))
        self.assertFalse(self.recovery_validator.validate_preflight(cyclic))
        self.assertFalse(self.recovery_validator.validate_preflight(deep))

        overflow_attempt = copy.deepcopy(self.recovery_contract)
        overflow_attempt["operation_intent"]["pre_run_attempt"] = MAX_SAFE_INTEGER
        overflow_attempt["operation_intent"]["expected_run_attempt"] = (
            MAX_SAFE_INTEGER + 1
        )
        self.assertFalse(self.recovery_validator.validate_preflight(overflow_attempt))

        unsafe_completion = copy.deepcopy(self.completion_receipt)
        unsafe_completion["returned_run_id"] = 9_007_199_254_740_993
        self.assertFalse(
            self.recovery_validator.validate_completion(
                unsafe_completion, self.recovery_contract
            )
        )
        self.assertFalse(
            self.recovery_validator.validate_completion(cyclic, self.recovery_contract)
        )

    def test_recovery_numeric_counts_and_attempts_reject_boolean_aliases(
        self,
    ) -> None:
        producer_fields = self.carriers["required_report_schema"][
            "parent_input_profiles"
        ]["merge_status_producer_implementation_receipt"]

        def rehash(contract: dict[str, object]) -> None:
            resolution = contract["dependency_edge_resolution_receipt"]
            for record in resolution["records"]:
                record["record_sha256"] = _canonical_sha256(
                    {k: v for k, v in record.items() if k != "record_sha256"}
                )
            resolution["records_sha256"] = _canonical_sha256(resolution["records"])
            resolution["edges_sha256"] = _canonical_sha256(resolution["edges"])
            resolution["receipt_sha256"] = _receipt_sha256(resolution)
            contract["repeat_safety"]["operation_identity_sha256"] = _canonical_sha256(
                contract["operation_intent"]
            )
            contract["preflight_sha256"] = _canonical_sha256(
                {k: v for k, v in contract.items() if k != "preflight_sha256"}
            )

        def validator_for(
            contract: dict[str, object],
        ) -> _RecoveryContractValidator:
            resolution = contract["dependency_edge_resolution_receipt"]
            return _RecoveryContractValidator(
                self.recovery_schema,
                self.producer_receipt,
                producer_fields,
                self.platform_observation,
                self.dispatch_delivery_receipt,
                self.dispatch_delivery_receipt["receipt_sha256"],
                resolution,
                resolution["resolver_anchor"],
                contract["pre_mutation_run_observation"],
                self.post_current_observation,
                self.acquisition_transaction,
            )

        for field in ("record_count", "edge_count"):
            with self.subTest(resolution_count=field):
                contract = copy.deepcopy(self.recovery_contract)
                resolution = contract["dependency_edge_resolution_receipt"]
                resolution[field] = bool(resolution[field])
                rehash(contract)
                self.assertFalse(validator_for(contract).validate_preflight(contract))

        for index, source_record in enumerate(
            self.recovery_contract["dependency_edge_resolution_receipt"]["records"]
        ):
            with self.subTest(discovered_reference_count=index):
                contract = copy.deepcopy(self.recovery_contract)
                record = contract["dependency_edge_resolution_receipt"]["records"][
                    index
                ]
                record["discovered_reference_count"] = bool(
                    source_record["discovered_reference_count"]
                )
                rehash(contract)
                self.assertFalse(validator_for(contract).validate_preflight(contract))

        for field in ("pre_run_attempt", "expected_run_attempt"):
            with self.subTest(operation_attempt=field):
                contract = copy.deepcopy(self.recovery_contract)
                operation = contract["operation_intent"]
                operation[field] = bool(operation[field])
                rehash(contract)
                self.assertFalse(validator_for(contract).validate_preflight(contract))

    def test_recovery_id_and_authentication_joins_reject_boolean_aliases(
        self,
    ) -> None:
        producer_fields = self.carriers["required_report_schema"][
            "parent_input_profiles"
        ]["merge_status_producer_implementation_receipt"]

        def rehash_preflight(
            contract: dict[str, object], producer: dict[str, object]
        ) -> None:
            producer["receipt_sha256"] = _receipt_sha256(producer)
            resolution = contract["dependency_edge_resolution_receipt"]
            resolution["implementation_receipt_sha256"] = producer["receipt_sha256"]
            resolution["receipt_sha256"] = _receipt_sha256(resolution)
            before = contract["pre_mutation_run_observation"]
            before["receipt_sha256"] = _receipt_sha256(before)
            contract["repeat_safety"]["operation_identity_sha256"] = _canonical_sha256(
                contract["operation_intent"]
            )
            contract["preflight_sha256"] = _canonical_sha256(
                {
                    key: value
                    for key, value in contract.items()
                    if key != "preflight_sha256"
                }
            )

        def preflight_validator(
            contract: dict[str, object], producer: dict[str, object]
        ) -> _RecoveryContractValidator:
            resolution = contract["dependency_edge_resolution_receipt"]
            return _RecoveryContractValidator(
                self.recovery_schema,
                producer,
                producer_fields,
                self.platform_observation,
                self.dispatch_delivery_receipt,
                self.dispatch_delivery_receipt["receipt_sha256"],
                resolution,
                resolution["resolver_anchor"],
                contract["pre_mutation_run_observation"],
                self.post_current_observation,
                self.acquisition_transaction,
            )

        def id_join_fixture() -> tuple[dict[str, object], dict[str, object]]:
            contract = copy.deepcopy(self.recovery_contract)
            producer = copy.deepcopy(self.producer_receipt)
            producer["run_id"] = 1
            producer["workflow_id"] = 1
            implementation = contract["implementation_receipt_identity"]
            implementation["receipt_sha256"] = ""
            implementation["run_id"] = 1
            implementation["workflow_id"] = 1
            operation = contract["operation_intent"]
            operation["run_id"] = 1
            operation["workflow_id"] = 1
            before = contract["pre_mutation_run_observation"]
            before["query_endpoint"] = f"/repos/{contract['repository']}/actions/runs/1"
            before["run_id"] = 1
            before["workflow_id"] = 1
            rehash_preflight(contract, producer)
            implementation["receipt_sha256"] = producer["receipt_sha256"]
            rehash_preflight(contract, producer)
            return contract, producer

        for receipt, field in (
            ("implementation_receipt_identity", "run_id"),
            ("implementation_receipt_identity", "workflow_id"),
            ("operation_intent", "run_id"),
            ("operation_intent", "workflow_id"),
        ):
            with self.subTest(receipt=receipt, field=field):
                contract, producer = id_join_fixture()
                validator = preflight_validator(contract, producer)
                self.assertTrue(validator.validate_preflight(contract))
                contract[receipt][field] = True
                rehash_preflight(contract, producer)
                self.assertFalse(validator.validate_preflight(contract))

        contract = copy.deepcopy(self.recovery_contract)
        producer = copy.deepcopy(self.producer_receipt)
        before = contract["pre_mutation_run_observation"]
        before["platform_identity"]["authenticated"] = 1
        rehash_preflight(contract, producer)
        self.assertFalse(
            preflight_validator(contract, producer).validate_preflight(contract)
        )

        for observation_name in ("platform", "current"):
            with self.subTest(observation=observation_name):
                observation = copy.deepcopy(self.platform_observation)
                current = copy.deepcopy(self.post_current_observation)
                transaction = copy.deepcopy(self.acquisition_transaction)
                completion = copy.deepcopy(self.completion_receipt)
                target = observation if observation_name == "platform" else current
                target["platform_identity"]["authenticated"] = 1
                target["receipt_sha256"] = _receipt_sha256(target)
                transaction["exact_attempt_observation_sha256"] = observation[
                    "receipt_sha256"
                ]
                transaction["current_run_observation_sha256"] = current[
                    "receipt_sha256"
                ]
                transaction["receipt_sha256"] = _receipt_sha256(transaction)
                completion["platform_observation_receipt_sha256"] = observation[
                    "receipt_sha256"
                ]
                completion["post_current_observation_receipt_sha256"] = current[
                    "receipt_sha256"
                ]
                completion["acquisition_transaction_receipt_sha256"] = transaction[
                    "receipt_sha256"
                ]
                completion["completion_sha256"] = _canonical_sha256(
                    {
                        key: value
                        for key, value in completion.items()
                        if key != "completion_sha256"
                    }
                )
                validator = _RecoveryContractValidator(
                    self.recovery_schema,
                    self.producer_receipt,
                    producer_fields,
                    observation,
                    self.dispatch_delivery_receipt,
                    self.dispatch_delivery_receipt["receipt_sha256"],
                    self.recovery_contract["dependency_edge_resolution_receipt"],
                    self.recovery_contract["dependency_edge_resolution_receipt"][
                        "resolver_anchor"
                    ],
                    self.recovery_contract["pre_mutation_run_observation"],
                    current,
                    transaction,
                )
                self.assertFalse(
                    validator.validate_completion(completion, self.recovery_contract)
                )

    def test_recovery_independent_parent_receipts_preserve_types(
        self,
    ) -> None:
        producer_fields = self.carriers["required_report_schema"][
            "parent_input_profiles"
        ]["merge_status_producer_implementation_receipt"]

        def validator_for(
            *,
            expected_resolution: dict[str, object] | None = None,
            expected_before: dict[str, object] | None = None,
        ) -> _RecoveryContractValidator:
            resolution = self.recovery_contract["dependency_edge_resolution_receipt"]
            return _RecoveryContractValidator(
                self.recovery_schema,
                self.producer_receipt,
                producer_fields,
                self.platform_observation,
                self.dispatch_delivery_receipt,
                self.dispatch_delivery_receipt["receipt_sha256"],
                resolution if expected_resolution is None else expected_resolution,
                resolution["resolver_anchor"],
                self.recovery_contract["pre_mutation_run_observation"]
                if expected_before is None
                else expected_before,
                self.post_current_observation,
                self.acquisition_transaction,
            )

        contract = copy.deepcopy(self.recovery_contract)
        self.assertTrue(validator_for().validate_preflight(contract))

        expected_before = copy.deepcopy(contract["pre_mutation_run_observation"])
        expected_before["platform_identity"]["authenticated"] = 1
        self.assertTrue(
            contract["pre_mutation_run_observation"]["platform_identity"][
                "authenticated"
            ]
            is True
        )
        self.assertEqual(
            expected_before["receipt_sha256"],
            contract["pre_mutation_run_observation"]["receipt_sha256"],
        )
        self.assertEqual(expected_before, contract["pre_mutation_run_observation"])
        self.assertFalse(
            _type_preserving_equal(
                expected_before, contract["pre_mutation_run_observation"]
            )
        )
        self.assertFalse(
            validator_for(expected_before=expected_before).validate_preflight(contract)
        )

        expected_resolution = copy.deepcopy(
            contract["dependency_edge_resolution_receipt"]
        )
        record_index = next(
            index
            for index, item in enumerate(expected_resolution["records"])
            if item["discovered_reference_count"] == 1
        )
        record = expected_resolution["records"][record_index]
        record["discovered_reference_count"] = True
        embedded_resolution = contract["dependency_edge_resolution_receipt"]
        embedded_count = embedded_resolution["records"][record_index][
            "discovered_reference_count"
        ]
        self.assertIs(type(embedded_count), int)
        self.assertEqual(
            embedded_count,
            1,
        )
        self.assertEqual(
            expected_resolution["receipt_sha256"],
            embedded_resolution["receipt_sha256"],
        )
        self.assertEqual(
            expected_resolution["records"][record_index]["record_sha256"],
            embedded_resolution["records"][record_index]["record_sha256"],
        )
        self.assertEqual(expected_resolution, embedded_resolution)
        self.assertFalse(
            _type_preserving_equal(expected_resolution, embedded_resolution)
        )
        self.assertFalse(
            validator_for(expected_resolution=expected_resolution).validate_preflight(
                contract
            )
        )

    def test_recovery_refs_and_endpoints_preserve_non_repository_bytes(self) -> None:
        def validate_before(**updates: str) -> bool:
            contract = copy.deepcopy(self.recovery_contract)
            before = contract["pre_mutation_run_observation"]
            before.update(updates)
            before["receipt_sha256"] = _receipt_sha256(before)
            contract["preflight_sha256"] = _canonical_sha256(
                {
                    key: value
                    for key, value in contract.items()
                    if key != "preflight_sha256"
                }
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
                contract["dependency_edge_resolution_receipt"],
                contract["dependency_edge_resolution_receipt"]["resolver_anchor"],
                before,
                self.post_current_observation,
                self.acquisition_transaction,
            )
            return validator.validate_preflight(contract)

        workflow_ref = self.producer_receipt["workflow_ref"]
        mixed_case_ref = workflow_ref.replace(
            "octo/review-fixture", "OcTo/Review-Fixture", 1
        )
        self.assertTrue(validate_before(workflow_ref=mixed_case_ref))
        for name, updates in (
            ("ref-trailing-tab", {"workflow_ref": workflow_ref + "\t"}),
            ("ref-empty-query", {"workflow_ref": workflow_ref + "?"}),
            (
                "endpoint-trailing-tab",
                {
                    "query_endpoint": (
                        self.recovery_contract["pre_mutation_run_observation"][
                            "query_endpoint"
                        ]
                        + "\t"
                    )
                },
            ),
            (
                "endpoint-empty-query",
                {
                    "query_endpoint": (
                        self.recovery_contract["pre_mutation_run_observation"][
                            "query_endpoint"
                        ]
                        + "?"
                    )
                },
            ),
        ):
            with self.subTest(malformed_recovery_value=name):
                self.assertFalse(validate_before(**updates))

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
            "endpoint-trailing-tab": lambda value: value.update(
                request_endpoint=value["request_endpoint"] + "\t"
            ),
            "endpoint-empty-query": lambda value: value.update(
                request_endpoint=value["request_endpoint"] + "?"
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
            "previous-uppercase-scheme": lambda run: run.update(
                previous_attempt_url=run["previous_attempt_url"].replace(
                    "https://", "HTTPS://", 1
                )
            ),
            "previous-empty-query": lambda run: run.update(
                previous_attempt_url=run["previous_attempt_url"] + "?"
            ),
            "previous-trailing-tab": lambda run: run.update(
                previous_attempt_url=run["previous_attempt_url"] + "\t"
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
                contract["pre_mutation_run_observation"],
                self.post_current_observation,
                self.acquisition_transaction,
            )

        def replace_closure_entry(
            producer: dict[str, object],
            contract: dict[str, object],
            old_entry: dict[str, object],
            new_entry: dict[str, object],
        ) -> None:
            producer["implementation_closure"] = [
                copy.deepcopy(new_entry) if entry == old_entry else entry
                for entry in producer["implementation_closure"]
            ]
            producer["implementation_closure"].sort(
                key=lambda entry: (
                    entry.get("repository", ""),
                    entry.get("commit", ""),
                    entry.get("path", ""),
                    entry.get("kind", ""),
                    entry.get("blob_sha256", ""),
                )
            )
            for identity_field in (
                "workflow_ref_identity",
                "job_workflow_ref_identity",
            ):
                identity = producer[identity_field]
                if identity["entry"] == old_entry:
                    identity.update(
                        repository=new_entry["repository"],
                        path=new_entry["path"],
                        resolved_commit=new_entry["commit"],
                        entry=copy.deepcopy(new_entry),
                        entry_sha256=_canonical_sha256(new_entry),
                    )
            producer["workflow_ref"] = (
                f"{producer['workflow_ref_identity']['repository']}/"
                f"{producer['workflow_ref_identity']['path']}@"
                f"{producer['workflow_ref_identity']['ref']}"
            )
            producer["job_workflow_ref"] = (
                f"{producer['job_workflow_ref_identity']['repository']}/"
                f"{producer['job_workflow_ref_identity']['path']}@"
                f"{producer['job_workflow_ref_identity']['ref']}"
            )
            resolution = contract["dependency_edge_resolution_receipt"]
            for record in resolution["records"]:
                if record["source_entry"] == old_entry:
                    record["source_entry"] = copy.deepcopy(new_entry)
                    record["source_sha256"] = new_entry["blob_sha256"]
                for reference in record["discovered_references"]:
                    if reference["target_entry"] == old_entry:
                        reference["target_entry"] = copy.deepcopy(new_entry)
                record["record_sha256"] = _canonical_sha256(
                    {
                        key: value
                        for key, value in record.items()
                        if key != "record_sha256"
                    }
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
            before = contract["pre_mutation_run_observation"]
            before["workflow_ref"] = producer["workflow_ref"]
            before["job_workflow_ref"] = producer["job_workflow_ref"]
            before["receipt_sha256"] = _receipt_sha256(before)

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

        self.assertTrue(
            self.recovery_validator.validate_preflight(self.recovery_contract)
        )
        self.assertNotEqual(
            self.producer_receipt["job_workflow_ref_identity"]["repository"],
            self.recovery_contract["repository"],
        )
        self.assertEqual(
            self.producer_receipt["job_workflow_ref_identity"]["entry"]["kind"],
            "reusable-workflow",
        )
        self.assertIn(
            "action",
            {
                entry["kind"]
                for entry in self.producer_receipt["implementation_closure"]
                if entry["repository"] != self.recovery_contract["repository"]
            },
        )

        for root_kind in ("action", "script"):
            with self.subTest(root_identity_kind=root_kind):
                producer = copy.deepcopy(self.producer_receipt)
                contract = copy.deepcopy(self.recovery_contract)
                old_root = copy.deepcopy(producer["workflow_ref_identity"]["entry"])
                attacked_root = copy.deepcopy(old_root)
                attacked_root["kind"] = root_kind
                replace_closure_entry(producer, contract, old_root, attacked_root)
                validator = rebuild(producer, contract)
                self.assertFalse(validator.validate_preflight(contract))

        producer = copy.deepcopy(self.producer_receipt)
        contract = copy.deepcopy(self.recovery_contract)
        old_root = copy.deepcopy(producer["workflow_ref_identity"]["entry"])
        external_root = copy.deepcopy(old_root)
        external_root["repository"] = "octo/external-root"
        replace_closure_entry(producer, contract, old_root, external_root)
        producer["workflow_repository"] = external_root["repository"]
        validator = rebuild(producer, contract)
        self.assertFalse(validator.validate_preflight(contract))

        producer = copy.deepcopy(self.producer_receipt)
        contract = copy.deepcopy(self.recovery_contract)
        duplicate_root = copy.deepcopy(producer["workflow_ref_identity"]["entry"])
        duplicate_root["blob_sha256"] = "a" * 64
        producer["implementation_closure"].append(duplicate_root)
        producer["implementation_closure"].sort(
            key=lambda entry: (
                entry["repository"],
                entry["commit"],
                entry["path"],
                entry["kind"],
                entry["blob_sha256"],
            )
        )
        producer["implementation_closure_count"] = len(
            producer["implementation_closure"]
        )
        duplicate_record = {
            "source_entry": copy.deepcopy(duplicate_root),
            "parser_profile": "github-actions-dependency-resolver-v1",
            "source_sha256": duplicate_root["blob_sha256"],
            "discovered_references": [],
            "discovered_reference_count": 0,
            "record_sha256": "",
        }
        duplicate_record["record_sha256"] = _canonical_sha256(
            {
                key: value
                for key, value in duplicate_record.items()
                if key != "record_sha256"
            }
        )
        resolution = contract["dependency_edge_resolution_receipt"]
        resolution["records"].append(duplicate_record)
        resolution["records"].sort(
            key=lambda record: (
                record["source_entry"]["repository"],
                record["source_entry"]["commit"],
                record["source_entry"]["path"],
                record["source_entry"]["kind"],
                record["source_entry"]["blob_sha256"],
            )
        )
        resolution["record_count"] = len(resolution["records"])
        resolution["records_sha256"] = _canonical_sha256(resolution["records"])
        validator = rebuild(producer, contract)
        self.assertFalse(validator.validate_preflight(contract))

        def add_action_target(
            new_action_entry: dict[str, object], reference: str
        ) -> tuple[_RecoveryContractValidator, dict[str, object]]:
            producer = copy.deepcopy(self.producer_receipt)
            contract = copy.deepcopy(self.recovery_contract)
            original_action = next(
                entry
                for entry in producer["implementation_closure"]
                if entry["kind"] == "action"
            )
            producer["implementation_closure"].append(copy.deepcopy(new_action_entry))
            producer["implementation_closure"].sort(
                key=lambda entry: (
                    entry["repository"],
                    entry["commit"],
                    entry["path"],
                    entry["kind"],
                    entry["blob_sha256"],
                )
            )
            producer["implementation_closure_count"] = len(
                producer["implementation_closure"]
            )

            resolution = contract["dependency_edge_resolution_receipt"]
            original_record = next(
                record
                for record in resolution["records"]
                if record["source_entry"] == original_action
            )
            new_record = copy.deepcopy(original_record)
            new_record["source_entry"] = copy.deepcopy(new_action_entry)
            new_record["source_sha256"] = new_action_entry["blob_sha256"]
            new_record["record_sha256"] = _canonical_sha256(
                {
                    key: value
                    for key, value in new_record.items()
                    if key != "record_sha256"
                }
            )
            resolution["records"].append(new_record)
            inbound_record = next(
                record
                for record in resolution["records"]
                if any(
                    dependency["target_entry"] == original_action
                    for dependency in record["discovered_references"]
                )
            )
            inbound_record["discovered_references"].append(
                {
                    "reference": reference,
                    "target_entry": copy.deepcopy(new_action_entry),
                }
            )
            inbound_record["discovered_references"].sort(
                key=lambda item: (
                    item["reference"],
                    item["target_entry"]["repository"],
                    item["target_entry"]["commit"],
                    item["target_entry"]["path"],
                    item["target_entry"]["kind"],
                    item["target_entry"]["blob_sha256"],
                )
            )
            inbound_record["discovered_reference_count"] = len(
                inbound_record["discovered_references"]
            )
            inbound_record["record_sha256"] = _canonical_sha256(
                {
                    key: value
                    for key, value in inbound_record.items()
                    if key != "record_sha256"
                }
            )
            resolution["records"].sort(
                key=lambda record: (
                    record["source_entry"]["repository"],
                    record["source_entry"]["commit"],
                    record["source_entry"]["path"],
                    record["source_entry"]["kind"],
                    record["source_entry"]["blob_sha256"],
                )
            )
            resolution["record_count"] = len(resolution["records"])
            resolution["records_sha256"] = _canonical_sha256(resolution["records"])
            resolution["edges"].append(
                {
                    "source_entry": copy.deepcopy(inbound_record["source_entry"]),
                    "reference": reference,
                    "target_entry": copy.deepcopy(new_action_entry),
                }
            )
            resolution["edges"].sort(
                key=lambda edge: (
                    edge["source_entry"]["repository"],
                    edge["source_entry"]["commit"],
                    edge["source_entry"]["path"],
                    edge["source_entry"]["kind"],
                    edge["source_entry"]["blob_sha256"],
                    edge["reference"],
                    edge["target_entry"]["repository"],
                    edge["target_entry"]["commit"],
                    edge["target_entry"]["path"],
                    edge["target_entry"]["kind"],
                    edge["target_entry"]["blob_sha256"],
                )
            )
            resolution["edge_count"] = len(resolution["edges"])
            resolution["edges_sha256"] = _canonical_sha256(resolution["edges"])
            return rebuild(producer, contract), contract

        baseline_action = next(
            entry
            for entry in self.producer_receipt["implementation_closure"]
            if entry["kind"] == "action"
        )
        independent_action = {
            **copy.deepcopy(baseline_action),
            "path": "actions/other/action.yaml",
            "blob_sha256": "b" * 64,
        }
        independent_validator, independent_contract = add_action_target(
            independent_action,
            f"{independent_action['repository']}/actions/other@"
            f"{independent_action['commit']}",
        )
        self.assertTrue(independent_validator.validate_preflight(independent_contract))

        for name, new_action, reference in (
            (
                "same-path-different-blob",
                {**copy.deepcopy(baseline_action), "blob_sha256": "a" * 64},
                f"{baseline_action['repository']}/actions/verify@"
                f"{baseline_action['commit']}",
            ),
            (
                "same-directory-alternate-manifest",
                {
                    **copy.deepcopy(baseline_action),
                    "path": "actions/verify/action.yaml",
                    "blob_sha256": "c" * 64,
                },
                f"{baseline_action['repository']}/actions/verify@"
                f"{baseline_action['commit']}",
            ),
        ):
            with self.subTest(action_selector_ambiguity=name):
                validator, attacked_contract = add_action_target(new_action, reference)
                self.assertFalse(validator.validate_preflight(attacked_contract))

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
                with self.assertRaises(ValueError):
                    rebuild(producer, contract)

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

    def test_recovery_repository_identity_is_case_insensitive(self) -> None:
        producer_fields = self.carriers["required_report_schema"][
            "parent_input_profiles"
        ]["merge_status_producer_implementation_receipt"]

        def validator_for(
            contract: dict[str, object],
            producer: dict[str, object] | None = None,
        ) -> _RecoveryContractValidator:
            selected_producer = producer or self.producer_receipt
            resolution = contract["dependency_edge_resolution_receipt"]
            return _RecoveryContractValidator(
                self.recovery_schema,
                selected_producer,
                producer_fields,
                self.platform_observation,
                self.dispatch_delivery_receipt,
                self.dispatch_delivery_receipt["receipt_sha256"],
                resolution,
                resolution["resolver_anchor"],
                contract["pre_mutation_run_observation"],
                self.post_current_observation,
                self.acquisition_transaction,
            )

        def rehash_resolution(contract: dict[str, object]) -> None:
            resolution = contract["dependency_edge_resolution_receipt"]
            for record in resolution["records"]:
                record["record_sha256"] = _canonical_sha256(
                    {
                        key: value
                        for key, value in record.items()
                        if key != "record_sha256"
                    }
                )
            resolution["record_count"] = len(resolution["records"])
            resolution["records_sha256"] = _canonical_sha256(resolution["records"])
            resolution["edge_count"] = len(resolution["edges"])
            resolution["edges_sha256"] = _canonical_sha256(resolution["edges"])
            resolution["resolver_anchor"]["receipt_sha256"] = _receipt_sha256(
                resolution["resolver_anchor"]
            )
            resolution["receipt_sha256"] = _receipt_sha256(resolution)
            contract["preflight_sha256"] = _canonical_sha256(
                {
                    key: value
                    for key, value in contract.items()
                    if key != "preflight_sha256"
                }
            )

        mixed_case_contract = copy.deepcopy(self.recovery_contract)
        mixed_resolution = mixed_case_contract["dependency_edge_resolution_receipt"]
        for record in mixed_resolution["records"]:
            for dependency in record["discovered_references"]:
                owner, repository, suffix = dependency["reference"].split("/", 2)
                dependency["reference"] = (
                    f"{owner.upper()}/{repository.upper()}/{suffix}"
                )
        for edge in mixed_resolution["edges"]:
            owner, repository, suffix = edge["reference"].split("/", 2)
            edge["reference"] = f"{owner.upper()}/{repository.upper()}/{suffix}"
        rehash_resolution(mixed_case_contract)
        self.assertTrue(
            validator_for(mixed_case_contract).validate_preflight(mixed_case_contract)
        )

        candidate_alias_contract = copy.deepcopy(self.recovery_contract)
        source = candidate_alias_contract["source_descriptor"]
        source.update(
            source_repository=candidate_alias_contract["repository"].upper(),
            source_commit="d" * 40,
        )
        source_anchor = candidate_alias_contract["source_trust_anchor"]
        source_anchor["identity"] = (
            f"{source['source_repository']}@{source['source_commit']}:"
            f"{source['source_path']}"
        )
        exclusion = candidate_alias_contract["candidate_range_exclusion_receipt"]
        exclusion["source"] = copy.deepcopy(source)
        alias_resolution = candidate_alias_contract[
            "dependency_edge_resolution_receipt"
        ]
        alias_resolution["resolver_anchor"]["candidate_range_exclusion_sha256"] = (
            _canonical_sha256(exclusion)
        )
        rehash_resolution(candidate_alias_contract)
        self.assertFalse(
            validator_for(candidate_alias_contract).validate_preflight(
                candidate_alias_contract
            )
        )

        for malformed_repository in ("Öcto/review-fixture", "owner/repo?"):
            with self.subTest(malformed_external_source=malformed_repository):
                malformed_contract = copy.deepcopy(self.recovery_contract)
                malformed_source = malformed_contract["source_descriptor"]
                malformed_source["source_repository"] = malformed_repository
                malformed_anchor = malformed_contract["source_trust_anchor"]
                malformed_anchor["identity"] = (
                    f"{malformed_source['source_repository']}@"
                    f"{malformed_source['source_commit']}:"
                    f"{malformed_source['source_path']}"
                )
                malformed_exclusion = malformed_contract[
                    "candidate_range_exclusion_receipt"
                ]
                malformed_exclusion["source"] = copy.deepcopy(malformed_source)
                malformed_resolution = malformed_contract[
                    "dependency_edge_resolution_receipt"
                ]
                malformed_resolution["resolver_anchor"][
                    "candidate_range_exclusion_sha256"
                ] = _canonical_sha256(malformed_exclusion)
                rehash_resolution(malformed_contract)
                self.assertFalse(
                    validator_for(malformed_contract).validate_preflight(
                        malformed_contract
                    )
                )

            with self.subTest(malformed_external_resolver=malformed_repository):
                malformed_contract = copy.deepcopy(self.recovery_contract)
                malformed_resolution = malformed_contract[
                    "dependency_edge_resolution_receipt"
                ]
                malformed_resolution["resolver_anchor"]["repository"] = (
                    malformed_repository
                )
                rehash_resolution(malformed_contract)
                self.assertFalse(
                    validator_for(malformed_contract).validate_preflight(
                        malformed_contract
                    )
                )

        for unsafe_resolver_path in (".", "resolvers/resolve\0.py"):
            with self.subTest(unsafe_resolver_path=unsafe_resolver_path):
                unsafe_contract = copy.deepcopy(self.recovery_contract)
                unsafe_resolution = unsafe_contract[
                    "dependency_edge_resolution_receipt"
                ]
                unsafe_resolution["resolver_anchor"]["path"] = unsafe_resolver_path
                rehash_resolution(unsafe_contract)
                self.assertFalse(
                    validator_for(unsafe_contract).validate_preflight(unsafe_contract)
                )

        duplicate_producer = copy.deepcopy(self.producer_receipt)
        duplicate_contract = copy.deepcopy(self.recovery_contract)
        original_action = next(
            entry
            for entry in duplicate_producer["implementation_closure"]
            if entry["kind"] == "action"
        )
        alias_action = copy.deepcopy(original_action)
        alias_action["repository"] = alias_action["repository"].replace(
            "z-recovery-policy", "z-RECOVERY-POLICY"
        )
        duplicate_producer["implementation_closure"].append(alias_action)
        duplicate_producer["implementation_closure"].sort(
            key=lambda entry: (
                _repository_identity(entry["repository"]),
                entry["repository"],
                entry["commit"],
                entry["path"],
                entry["kind"],
                entry["blob_sha256"],
            )
        )
        duplicate_producer["implementation_closure_count"] = len(
            duplicate_producer["implementation_closure"]
        )
        duplicate_producer["implementation_closure_sha256"] = _canonical_sha256(
            duplicate_producer["implementation_closure"]
        )
        duplicate_producer["receipt_sha256"] = _receipt_sha256(duplicate_producer)
        duplicate_contract["implementation_receipt_identity"]["receipt_sha256"] = (
            duplicate_producer["receipt_sha256"]
        )
        duplicate_resolution = duplicate_contract["dependency_edge_resolution_receipt"]
        duplicate_resolution["implementation_receipt_sha256"] = duplicate_producer[
            "receipt_sha256"
        ]
        alias_record = {
            "source_entry": copy.deepcopy(alias_action),
            "parser_profile": "github-actions-dependency-resolver-v1",
            "source_sha256": alias_action["blob_sha256"],
            "discovered_references": [],
            "discovered_reference_count": 0,
            "record_sha256": "",
        }
        duplicate_resolution["records"].append(alias_record)
        inbound_record = next(
            record
            for record in duplicate_resolution["records"]
            if any(
                dependency["target_entry"] == original_action
                for dependency in record["discovered_references"]
            )
        )
        alias_reference = {
            "reference": (
                f"{alias_action['repository']}/actions/verify@{alias_action['commit']}"
            ),
            "target_entry": copy.deepcopy(alias_action),
        }
        inbound_record["discovered_references"].append(alias_reference)
        inbound_record["discovered_references"].sort(
            key=lambda item: (item["reference"],)
        )
        inbound_record["discovered_reference_count"] = len(
            inbound_record["discovered_references"]
        )
        duplicate_resolution["records"].sort(
            key=lambda record: (
                _repository_identity(record["source_entry"]["repository"]),
                record["source_entry"]["repository"],
                record["source_entry"]["commit"],
                record["source_entry"]["path"],
                record["source_entry"]["kind"],
                record["source_entry"]["blob_sha256"],
            )
        )
        duplicate_resolution["edges"].append(
            {
                "source_entry": copy.deepcopy(inbound_record["source_entry"]),
                **copy.deepcopy(alias_reference),
            }
        )
        duplicate_resolution["edges"].sort(
            key=lambda edge: (
                _repository_identity(edge["source_entry"]["repository"]),
                edge["source_entry"]["repository"],
                edge["source_entry"]["commit"],
                edge["source_entry"]["path"],
                edge["source_entry"]["kind"],
                edge["source_entry"]["blob_sha256"],
                edge["reference"],
                _repository_identity(edge["target_entry"]["repository"]),
                edge["target_entry"]["repository"],
                edge["target_entry"]["commit"],
                edge["target_entry"]["path"],
                edge["target_entry"]["kind"],
                edge["target_entry"]["blob_sha256"],
            )
        )
        rehash_resolution(duplicate_contract)
        self.assertFalse(
            validator_for(duplicate_contract, duplicate_producer).validate_preflight(
                duplicate_contract
            )
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
