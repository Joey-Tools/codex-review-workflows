from __future__ import annotations

import copy
import datetime
import hashlib
import json
import pathlib
import re
import unittest
import urllib.parse


SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
GRAMMAR_PATH = SKILL_ROOT / "references/github-codex-terminal-carriers-v1.json"
AUTHORITY_PATH = SKILL_ROOT / "references/github-codex-evidence-authority.md"
FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")
MARKER = re.compile(r"\*\*Reviewed commit:\*\* `([0-9a-f]{10}|[0-9a-f]{40})`\Z")
FINDING = re.compile(r"- \[P[0-3]\] (.{1,240}) — (https://[^\s]+)\Z")
RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


def _merge_patch(target: object, patch: object) -> object:
    if not isinstance(patch, dict):
        return copy.deepcopy(patch)
    result = copy.deepcopy(target) if isinstance(target, dict) else {}
    for key, value in patch.items():
        if value is None:
            result.pop(key, None)
        else:
            result[key] = _merge_patch(result.get(key), value)
    return result


def _normalize_body(value: object) -> str:
    if not isinstance(value, str) or any(
        0xD800 <= ord(character) <= 0xDFFF for character in value
    ):
        raise ValueError("body is not a Unicode scalar sequence")
    normalized = value.replace("\r\n", "\n")
    for source in ("\r", "\v", "\f", "\u0085", "\u2028", "\u2029"):
        normalized = normalized.replace(source, "\n")
    for character in normalized:
        codepoint = ord(character)
        if codepoint == 0 or (
            (codepoint < 0x20 or 0x7F <= codepoint <= 0x9F)
            and character not in {"\t", "\n"}
        ):
            raise ValueError("body contains a rejected control")
    return normalized.strip("\t\n ")


def _time(value: object) -> datetime.datetime:
    if not isinstance(value, str) or RFC3339.fullmatch(value) is None:
        raise ValueError("non-canonical server time")
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


class _ReferenceClassifier:
    """Bounded test-only reading of the four version-1 carrier branches."""

    def __init__(self, grammar: dict[str, object]) -> None:
        self.grammar = grammar
        identity = grammar["provider_identity"]
        self.user = {"login": identity["login"], "type": identity["type"]}
        self.app = {"slug": identity["issue_comment_app_slug"]}
        self.fields = grammar["closed_record_fields"]
        self.branches = grammar["branches"]
        self.ancestor_projection = grammar["ancestor_shas_projection"]

    @staticmethod
    def _result(
        classification: str,
        branch: str | None,
        semantic: tuple[str, str] | None,
        unresolved: int = 0,
    ) -> dict[str, object]:
        field, value = semantic or (None, None)
        return {
            "classification": classification,
            "branch": branch,
            "semantic_time_field": field,
            "semantic_time": value,
            "unresolved_findings": unresolved,
        }

    def _closed(self, value: object, profile: str) -> bool:
        return isinstance(value, dict) and set(value) == set(self.fields[profile])

    @staticmethod
    def _is_full_sha(value: object) -> bool:
        return isinstance(value, str) and FULL_SHA.fullmatch(value) is not None

    @staticmethod
    def _is_positive_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value > 0

    def _projection_status(self, scope: dict[str, object]) -> str | None:
        ancestors = scope["ancestor_shas"]
        projection = scope["ancestor_shas_projection"]
        if (
            not isinstance(ancestors, list)
            or not all(self._is_full_sha(sha) for sha in ancestors)
            or ancestors != sorted(set(ancestors))
            or scope["head_sha"] in ancestors
            or not self._closed(projection, "ancestor_shas_projection")
        ):
            return None
        digest_input = "".join(f"{sha}\n" for sha in ancestors).encode("ascii")
        expected_digest = hashlib.sha256(digest_input).hexdigest()
        count = projection["ancestor_count"]
        status = projection["status"]
        if (
            projection["owner"] != self.ancestor_projection["owner"]
            or status not in self.ancestor_projection["status_values"]
            or projection["repository"] != scope["repository"]
            or not self._is_positive_int(projection["pull_request"])
            or projection["pull_request"] != scope["pull_request"]
            or not self._is_full_sha(projection["base_sha"])
            or projection["base_sha"] != scope["base_sha"]
            or projection["base_sha"] in ancestors
            or projection["head_sha"] != scope["head_sha"]
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count != len(ancestors)
            or projection["ancestor_shas_sha256"] != expected_digest
        ):
            return None
        return status

    @staticmethod
    def _ancestor_applicability(scope: dict[str, object], commit: str) -> str:
        if commit == scope["head_sha"]:
            return "applicable"
        projection = scope["ancestor_shas_projection"]
        if projection["status"] != "complete":
            return "inconclusive"
        return "applicable" if commit in scope["ancestor_shas"] else "stale"

    def _semantic(self, record: dict[str, object]) -> tuple[str, str]:
        if record["kind"] == "review":
            _time(record["submitted_at"])
            return "submitted_at", record["submitted_at"]
        created = _time(record["created_at"])
        updated = _time(record["updated_at"])
        if updated < created:
            raise ValueError("edit precedes creation")
        return (
            ("created_at", record["created_at"])
            if updated == created
            else ("updated_at", record["updated_at"])
        )

    def classify(self, record: object) -> dict[str, object]:
        if not isinstance(record, dict) or record.get("kind") not in {
            "issue_comment",
            "review",
        }:
            return self._result("malformed", None, None)
        allowed = set(self.fields[record["kind"]])
        actual = set(record)
        if actual != allowed and not (
            record["kind"] == "review" and actual == allowed - {"state"}
        ):
            return self._result("malformed", None, None)
        if not self._is_positive_int(record["id"]):
            return self._result("malformed", None, None)
        if not self._closed(record["scope"], "scope"):
            return self._result("malformed", None, None)
        scope = record["scope"]
        if (
            not isinstance(scope["repository"], str)
            or not scope["repository"]
            or not self._is_positive_int(scope["pull_request"])
            or not self._is_full_sha(scope["base_sha"])
            or scope["base_sha"] == scope["head_sha"]
            or not self._is_full_sha(scope["head_sha"])
            or self._projection_status(scope) is None
        ):
            return self._result("malformed", None, None)
        if not self._closed(record["user"], "user"):
            return self._result("malformed", None, None)
        if record["user"] != self.user:
            return self._result("irrelevant", None, None)
        try:
            semantic = self._semantic(record)
            body = _normalize_body(record["body"])
        except (TypeError, ValueError):
            semantic = locals().get("semantic")
            return self._result("malformed", None, semantic)
        if record["kind"] == "issue_comment":
            return self._issue(record, body, semantic)
        return self._review(record, body, semantic)

    def _issue(
        self, record: dict[str, object], body: str, semantic: tuple[str, str]
    ) -> dict[str, object]:
        app = record["performed_via_github_app"]
        if not self._closed(app, "app"):
            return self._result("malformed", None, semantic)
        if app != self.app:
            return self._result("irrelevant", None, None)
        detector = self.grammar["terminal_detection"]["issue_comment"]
        first, _, later = body.partition("\n")
        position = first.find(detector["anchor"])
        if position < 0 or position > detector["first_line_max_start_scalar_index"]:
            return self._result("irrelevant", None, semantic)
        if any(
            character.isascii() and character.isalnum()
            for character in first[:position]
        ):
            return self._result("irrelevant", None, semantic)
        carrier = first[position:]
        if not any(line.strip("\t ") for line in later.split("\n")):
            for stem in detector["progress_stems"]:
                if carrier in {stem, f"{stem}."}:
                    return self._result("nonterminal", "progress", semantic)
                prefix = f"{stem}: "
                detail = carrier[len(prefix) :] if carrier.startswith(prefix) else ""
                if 1 <= len(detail) <= 160 and "\t" not in detail:
                    return self._result("nonterminal", "progress", semantic)
        if carrier.startswith(self.branches["clean_issue_v1"]["lead"]):
            return self._clean_issue(record, body[position:], semantic)
        finding = self._top_finding(record, body, semantic)
        if isinstance(finding, dict):
            return finding
        if finding is None:
            return self._result("malformed", None, semantic)
        commit, finding_count = finding
        applicability = self._ancestor_applicability(record["scope"], commit)
        if applicability != "applicable":
            return self._result(applicability, "top-level-finding-v1", semantic)
        return self._result("findings", "top-level-finding-v1", semantic, finding_count)

    def _clean_issue(
        self, record: dict[str, object], carrier: str, semantic: tuple[str, str]
    ) -> dict[str, object]:
        branch = self.branches["clean_issue_v1"]
        first, separator, rest = carrier.partition("\n")
        blank, second_separator, tail = rest.partition("\n")
        marker_line, suffix_separator, suffix = tail.partition("\n")
        marker = MARKER.fullmatch(marker_line)
        if separator != "\n" or blank or second_separator != "\n" or marker is None:
            return self._result("malformed", None, semantic)
        lead = branch["lead"]
        if first != lead:
            if not first.startswith(f"{lead} "):
                return self._result("malformed", None, semantic)
            tagline = first[len(lead) + 1 :]
            accepted = tagline in branch["allowed_tagline_symbols"] or any(
                tagline == f"{stem}{punctuation}"
                for stem in branch["allowed_tagline_stems"]
                for punctuation in branch["tagline_stem_terminal_punctuation"]
            )
            if not accepted:
                return self._result("malformed", None, semantic)
        if suffix_separator:
            if not suffix.startswith("\n"):
                return self._result("malformed", None, semantic)
            disclosure = suffix[1:]
            if not disclosure.split("\n", 1)[0].strip():
                return self._result("malformed", None, semantic)
            normalized_disclosure = tuple(
                line.strip() for line in disclosure.split("\n") if line.strip()
            )
            if normalized_disclosure != tuple(self.grammar["disclosure_lines"]):
                return self._result("malformed", None, semantic)
        commit_ref = marker.group(1)
        head = record["scope"]["head_sha"]
        resolution = record["commit_resolution"]
        if len(commit_ref) == 40:
            if resolution is not None:
                return self._result("malformed", None, semantic)
            if commit_ref != head:
                return self._result("stale", "clean-issue-v1", semantic)
        else:
            if not self._closed(resolution, "commit_resolution"):
                return self._result("malformed", None, semantic)
            if (
                resolution["repository"] != record["scope"]["repository"]
                or resolution["commit_ref"] != commit_ref
                or resolution["initial_resolved_commit"] != head
                or resolution["final_resolved_commit"] != head
                or not head.startswith(commit_ref)
            ):
                return self._result("malformed", None, semantic)
        return self._result("clean", "clean-issue-v1", semantic)

    def _review(
        self, record: dict[str, object], body: str, semantic: tuple[str, str]
    ) -> dict[str, object]:
        states = self.grammar["terminal_detection"]["review"]
        state = record.get("state")
        if state in states["nonterminal_states"]:
            return self._result("nonterminal", None, semantic)
        if state not in states["admitted_states"]:
            return self._result(
                "malformed" if body or record["children"] else "irrelevant",
                None,
                semantic,
            )
        finding = self._top_finding(record, body, semantic)
        if isinstance(finding, dict):
            return finding
        if finding is not None:
            joined = self._children(record, semantic, "top-level-finding-v1")
            if isinstance(joined, dict):
                return joined
            _, unresolved = joined
            commit, finding_count = finding
            applicability = self._ancestor_applicability(record["scope"], commit)
            if applicability != "applicable":
                return self._result(applicability, "top-level-finding-v1", semantic)
            return self._result(
                "findings",
                "top-level-finding-v1",
                semantic,
                finding_count + unresolved,
            )
        if state == "APPROVED":
            if body != self.branches["clean_review_v1"]["body"]:
                return self._result("malformed", None, semantic)
            if not self._is_full_sha(record["commit_id"]):
                return self._result("malformed", None, semantic)
            joined = self._children(record, semantic, "clean-review-v1")
            if isinstance(joined, dict):
                return joined
            count, unresolved = joined
            if count:
                applicability = self._ancestor_applicability(
                    record["scope"], record["commit_id"]
                )
                if applicability != "applicable":
                    return self._result(applicability, "inline-parent-v1", semantic)
                return self._result(
                    "findings", "inline-parent-v1", semantic, unresolved
                )
            if record["commit_id"] != record["scope"]["head_sha"]:
                return self._result("stale", "clean-review-v1", semantic)
            return self._result("clean", "clean-review-v1", semantic)
        if state == "COMMENTED" and record["children"]:
            return self._inline(record, body, semantic)
        return self._result("malformed", None, semantic)

    def _top_finding(
        self, record: dict[str, object], body: str, semantic: tuple[str, str]
    ) -> tuple[str, int] | dict[str, object] | None:
        branch = self.branches["top_level_finding_v1"]
        if not body.startswith(branch["header"]):
            return None
        carrier, disclosure_separator, disclosure = body.partition("\n\n")
        if disclosure_separator and disclosure != "\n".join(
            self.grammar["disclosure_lines"]
        ):
            return self._result("malformed", None, semantic)
        lines = carrier.split("\n")
        if lines[0] != branch["header"] or len(lines) < 2:
            return self._result("malformed", None, semantic)
        commits: set[str] = set()
        prefix = f"https://github.com/{record['scope']['repository']}/blob/"
        for line in lines[1:]:
            matched = FINDING.fullmatch(line)
            if not matched:
                return self._result("malformed", None, semantic)
            title, url = matched.groups()
            if (
                " — " in title
                or title[0] in "\t "
                or title[-1] in "\t "
                or "\t" in title
                or not url.startswith(prefix)
            ):
                return self._result("malformed", None, semantic)
            try:
                url.encode("ascii")
            except UnicodeEncodeError:
                return self._result("malformed", None, semantic)
            suffix = url[len(prefix) :]
            commit, separator, location = suffix.partition("/")
            path, anchor_separator, anchor = location.rpartition("#")
            if (
                not separator
                or FULL_SHA.fullmatch(commit) is None
                or not anchor_separator
                or re.fullmatch(r"L[1-9][0-9]*(?:-L[1-9][0-9]*)?", anchor) is None
                or re.fullmatch(
                    r"(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|%[0-9A-F]{2})+", path
                )
                is None
            ):
                return self._result("malformed", None, semantic)
            try:
                decoded_segments = (
                    urllib.parse.unquote_to_bytes(path).decode("utf-8").split("/")
                )
            except UnicodeDecodeError:
                return self._result("malformed", None, semantic)
            if any(segment in {"", ".", ".."} for segment in decoded_segments):
                return self._result("malformed", None, semantic)
            commits.add(commit)
        if len(commits) != 1:
            return self._result("malformed", None, semantic)
        commit = next(iter(commits))
        if record["kind"] == "review" and (
            record.get("state") not in branch["review_states"]
            or record["commit_id"] != commit
        ):
            return self._result("malformed", None, semantic)
        return commit, len(lines) - 1

    def _inline(
        self, record: dict[str, object], body: str, semantic: tuple[str, str]
    ) -> dict[str, object]:
        commit = record["commit_id"]
        if not self._is_full_sha(commit):
            return self._result("malformed", None, semantic)
        if body:
            lines = list(self.branches["inline_parent_v1"]["nonempty_parent_lines"])
            lines[-1] = lines[-1].replace("<PARENT_FULL_SHA>", commit)
            expected = "\n".join(lines + ["", *self.grammar["disclosure_lines"]])
            if body != expected:
                return self._result("malformed", None, semantic)
        joined = self._children(record, semantic, "inline-parent-v1")
        if isinstance(joined, dict):
            return joined
        count, unresolved = joined
        applicability = self._ancestor_applicability(record["scope"], commit)
        if applicability != "applicable":
            return self._result(applicability, "inline-parent-v1", semantic)
        return self._result(
            "findings" if count else "malformed",
            "inline-parent-v1" if count else None,
            semantic,
            unresolved,
        )

    def _children(
        self,
        record: dict[str, object],
        semantic: tuple[str, str],
        branch: str,
    ) -> tuple[int, int] | dict[str, object]:
        if (
            record["children_complete"] is not True
            or record["threads_complete"] is not True
        ):
            return self._result("inconclusive", branch, semantic)
        if not isinstance(record["children"], list):
            return self._result("malformed", None, semantic)
        targets = []
        for child in record["children"]:
            if not self._closed(child, "child") or not self._closed(
                child["user"], "user"
            ):
                return self._result("malformed", None, semantic)
            if not self._is_positive_int(child["id"]):
                return self._result("malformed", None, semantic)
            if child["user"] != self.user:
                continue
            if (
                not self._is_positive_int(child["pull_request_review_id"])
                or child["pull_request_review_id"] != record["id"]
            ):
                return self._result("malformed", None, semantic)
            expected_url = (
                f"https://github.com/{record['scope']['repository']}/pull/"
                f"{record['scope']['pull_request']}#discussion_r{child['id']}"
            )
            if child["url"] != expected_url:
                return self._result("malformed", None, semantic)
            targets.append(child)
        unresolved = 0
        seen_child_joins: set[tuple[object, object]] = set()
        seen_url_joins: set[tuple[object, object]] = set()
        for child in targets:
            join = child["thread_join"]
            if (
                child["commit_id"] != record["commit_id"]
                or child["original_commit_id"] != record["commit_id"]
                or not self._closed(join, "thread_join")
            ):
                return self._result("malformed", None, semantic)
            if (
                not self._is_positive_int(join["match_count"])
                or join["match_count"] != 1
                or not isinstance(join["isResolved"], bool)
            ):
                return self._result("inconclusive", branch, semantic)
            if (
                not isinstance(join["url"], str)
                or not self._is_positive_int(join["parent_review_id"])
                or join["parent_review_id"] != record["id"]
                or not self._is_positive_int(join["child_comment_id"])
                or join["child_comment_id"] != child["id"]
                or join["url"] != child["url"]
            ):
                return self._result("malformed", None, semantic)
            child_join = (join["parent_review_id"], join["child_comment_id"])
            url_join = (join["parent_review_id"], join["url"])
            if child_join in seen_child_joins or url_join in seen_url_joins:
                return self._result("inconclusive", branch, semantic)
            seen_child_joins.add(child_join)
            seen_url_joins.add(url_join)
            try:
                if not _normalize_body(child["body"]):
                    raise ValueError
            except ValueError:
                return self._result("malformed", None, semantic)
            unresolved += int(not join["isResolved"])
        return len(targets), unresolved


class _ReportValidator:
    """Closed test-only validator for the required report projection."""

    def __init__(self, grammar: dict[str, object]) -> None:
        self.grammar_name = grammar["schema"]
        self.schema = grammar["required_report_schema"]
        self.fields = self.schema["closed_fields"]
        self.rules = self.schema["basis_rules"]

    def _closed(self, value: object, profile: str) -> bool:
        return isinstance(value, dict) and set(value) == set(self.fields[profile])

    @staticmethod
    def _positive_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value > 0

    @staticmethod
    def _full_sha(value: object) -> bool:
        return isinstance(value, str) and FULL_SHA.fullmatch(value) is not None

    def _common_evidence(self, report: dict[str, object], evidence: object) -> bool:
        if not self._closed(evidence, "evidence"):
            return False
        try:
            _time(evidence["server_time"])
        except (TypeError, ValueError):
            return False
        request_id = evidence["request_id"]
        return (
            self._positive_int(evidence["id"])
            and isinstance(evidence["url"], str)
            and evidence["url"].startswith(
                f"https://github.com/{report['repository']}/"
            )
            and (request_id is None or self._positive_int(request_id))
        )

    def _terminal_evidence(self, report: dict[str, object], evidence: object) -> bool:
        if not self._common_evidence(report, evidence):
            return False
        field_by_channel = {
            "issue-comment": {"created_at", "updated_at"},
            "review": {"submitted_at"},
        }
        channel = evidence["channel"]
        if not isinstance(channel, str) or channel not in field_by_channel:
            return False
        return (
            evidence["kind"] == "terminal-artifact"
            and evidence["server_time_field"] in field_by_channel[channel]
            and evidence["grammar"] == self.grammar_name
            and evidence["grammar_status"] == "accepted"
            and self._full_sha(evidence["artifact_commit"])
            and evidence["head_binding"] == "explicit-commit"
        )

    def validate(self, report: object) -> bool:
        if not self._closed(report, "report"):
            return False
        if (
            report["status"] not in self.schema["status_values"]
            or not isinstance(report["repository"], str)
            or report["repository"].count("/") != 1
            or not self._positive_int(report["pull_request"])
            or not self._full_sha(report["head_sha"])
            or report["scope_assurance"] != "latest-head-only"
            or report["base_assurance"] != "local-pr-readiness"
            or not isinstance(report["unresolved_provider_findings"], list)
            or not isinstance(report["last_reason"], str)
            or not report["last_reason"]
            or not self._closed(report["request_policy"], "request_policy")
        ):
            return False
        policy = report["request_policy"]
        if (
            policy["status"] not in self.schema["request_policy_status_values"]
            or not isinstance(policy["warnings"], list)
            or not all(isinstance(warning, str) for warning in policy["warnings"])
        ):
            return False
        basis = report["basis"]
        evidence = report["evidence"]
        if basis == "terminal-clean":
            rule = self.rules[basis]
            return (
                report["status"] == rule["status"]
                and not report["unresolved_provider_findings"]
                and self._terminal_evidence(report, evidence)
                and evidence["kind"] == rule["evidence_kind"]
                and evidence["grammar_branch"] in rule["branches"]
                and evidence["artifact_commit"] == report["head_sha"]
                and evidence["head_binding"] == rule["head_binding"]
            )
        if basis == "reaction-clean":
            rule = self.rules[basis]
            return (
                report["status"] == rule["status"]
                and not report["unresolved_provider_findings"]
                and self._common_evidence(report, evidence)
                and evidence["kind"] == rule["evidence_kind"]
                and evidence["channel"] == "reaction"
                and evidence["grammar"] is None
                and evidence["grammar_branch"] is None
                and evidence["grammar_status"] is None
                and evidence["artifact_commit"] is None
                and evidence["server_time_field"] == "reaction-time"
                and evidence["head_binding"] == rule["head_binding"]
                and self._positive_int(evidence["request_id"])
            )
        if basis == "merge-status":
            rule = self.rules[basis]
            return (
                report["status"] == rule["status"]
                and not report["unresolved_provider_findings"]
                and self._common_evidence(report, evidence)
                and evidence["kind"] == rule["evidence_kind"]
                and evidence["channel"] == "merge-status"
                and evidence["grammar"] is None
                and evidence["grammar_branch"] is None
                and evidence["grammar_status"] is None
                and evidence["artifact_commit"] is None
                and evidence["server_time_field"] == "status-time"
                and evidence["head_binding"] == rule["head_binding"]
                and evidence["request_id"] is None
            )
        null_rule = self.rules["null"]
        if basis is not None:
            return False
        if evidence is None:
            return report["status"] in null_rule["null_evidence_statuses"]
        return (
            report["status"] == "findings"
            and self._terminal_evidence(report, evidence)
            and evidence["kind"] == null_rule["finding_evidence_kind"]
            and evidence["grammar_branch"] in null_rule["finding_branches"]
        )


class GitHubTerminalCarrierContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.grammar = json.loads(GRAMMAR_PATH.read_text(encoding="utf-8"))
        cls.classifier = _ReferenceClassifier(cls.grammar)
        cls.report_validator = _ReportValidator(cls.grammar)

    def test_resource_is_versioned_closed_and_consumer_only(self) -> None:
        self.assertEqual(self.grammar["schema"], "github-codex-terminal-carriers-v1")
        self.assertEqual(self.grammar["schema_version"], 1)
        self.assertEqual(self.grammar["role"], "consumer-terminal-carrier-grammar")
        self.assertEqual(self.grammar["producer_contract"], "out-of-scope")
        self.assertEqual(self.grammar["fixture_patch_semantics"], "RFC7396")
        self.assertEqual(
            self.grammar["terminal_commit_binding"]["hashless_branches"], []
        )
        self.assertEqual(
            self.grammar["ancestor_shas_projection"]["owner"],
            "parent-orchestrator",
        )
        self.assertEqual(
            set(self.grammar["ancestor_shas_projection"]["status_values"]),
            {"complete", "incomplete"},
        )
        self.assertEqual(
            set(self.grammar["closed_record_fields"]["ancestor_shas_projection"]),
            {
                "owner",
                "status",
                "repository",
                "pull_request",
                "base_sha",
                "head_sha",
                "ancestor_count",
                "ancestor_shas_sha256",
            },
        )
        self.assertIn(
            "child_comment_id",
            self.grammar["closed_record_fields"]["thread_join"],
        )
        self.assertEqual(
            set(self.grammar["branches"]),
            {
                "clean_issue_v1",
                "clean_review_v1",
                "top_level_finding_v1",
                "inline_parent_v1",
            },
        )
        self.assertEqual(
            self.grammar["closed_world"][
                "unknown_terminal_looking_exact_provider_carrier"
            ],
            "malformed",
        )
        report_schema = self.grammar["required_report_schema"]
        self.assertEqual(report_schema["schema"], "github-codex-lane-report-v1")
        self.assertEqual(report_schema["role"], "consumer-report-schema")
        self.assertEqual(report_schema["producer_contract"], "out-of-scope")
        self.assertEqual(
            report_schema["basis_rules"]["terminal-clean"]["artifact_commit"],
            "required-full-sha-equals-report-head",
        )
        self.assertEqual(
            report_schema["basis_rules"]["terminal-clean"]["head_binding"],
            "explicit-commit",
        )
        self.assertEqual(
            report_schema["basis_rules"]["reaction-clean"]["head_binding"],
            "stable-request-epoch",
        )

    def test_authority_strongly_links_the_consumer_grammar(self) -> None:
        authority = AUTHORITY_PATH.read_text(encoding="utf-8")
        for anchor in (
            "[github-codex-terminal-carriers-v1.json]",
            "normative version-1 consumer grammar and fixture matrix",
            "match an accepted branch is malformed",
            "The resource is deliberately a consumer contract",
            "authorize a GitHub Action",
            "A hashless issue comment is not a terminal carrier",
            "reserved for the reaction-only fallback",
            "grammar: github-codex-terminal-carriers-v1",
            "grammar_branch:",
            "grammar_status:",
            "artifact_commit:",
            "server_time_field:",
            "closed parent-owned `ancestor_shas_projection`",
            "`required_report_schema` and `report_fixtures`",
            "exact child comment ID, URL, and parent review ID",
            "`artifact_commit` is required, non-null, and equal",
            "`head_binding` is exactly `explicit-commit`",
            "`stable-request-epoch` is valid only in that `basis: reaction-clean`",
        ):
            self.assertIn(anchor, authority)
        self.assertNotIn("artifact_commit: 40-lowercase-hex-or-null", authority)

    def test_fixture_matrix_matches_the_reference_classifier(self) -> None:
        fixtures = self.grammar["fixtures"]
        fixture_ids = [fixture["id"] for fixture in fixtures]
        self.assertEqual(len(fixture_ids), len(set(fixture_ids)))
        required = {
            "clean-issue-positive",
            "clean-review-positive",
            "top-level-finding-positive",
            "top-level-ancestor-finding-positive",
            "top-level-multiple-findings",
            "inline-finding-unresolved",
            "inline-finding-resolved",
            "clean-review-with-inline-finding",
            "approved-ancestor-inline-finding",
            "approved-ancestor-inline-incomplete-projection",
            "approved-nonancestor-inline-finding",
            "ancestor-projection-count-mismatch",
            "ancestor-projection-digest-mismatch",
            "ancestor-projection-head-mismatch",
            "ancestor-projection-base-mismatch",
            "ancestor-projection-unknown-status",
            "ancestor-projection-open-field",
            "ancestor-inline-child-id-mismatch",
            "inline-child-url-id-mismatch",
            "inline-child-url-cross-scope",
            "top-level-with-inline-unresolved",
            "top-level-ancestor-with-inline-unresolved",
            "top-level-with-inline-resolved",
            "top-level-inline-child-id-mismatch",
            "top-level-with-inline-incomplete-join",
            "edited-clean-issue",
            "progress-issue",
            "provider-failure-terminal-looking",
            "hashless-clean-issue-near-miss",
            "clean-review-near-miss",
            "wrong-actor-copy",
            "old-head-clean-review",
            "inline-incomplete-join",
            "missing-state-terminal-review",
        }
        self.assertTrue(required.issubset(fixture_ids))
        for fixture in fixtures:
            with self.subTest(fixture=fixture["id"]):
                self.assertEqual(set(fixture), {"id", "base", "patch", "expected"})
                base = self.grammar["bases"][fixture["base"]]
                record = _merge_patch(base, fixture["patch"])
                self.assertEqual(self.classifier.classify(record), fixture["expected"])

    def test_required_report_matrix_is_closed_and_basis_discriminated(self) -> None:
        fixtures = self.grammar["report_fixtures"]
        fixture_ids = [fixture["id"] for fixture in fixtures]
        self.assertEqual(len(fixture_ids), len(set(fixture_ids)))
        required = {
            "terminal-clean-report-positive",
            "terminal-clean-null-artifact-commit",
            "terminal-clean-stable-request-epoch",
            "terminal-clean-artifact-commit-mismatch",
            "terminal-clean-reaction-kind-mismatch",
            "terminal-clean-open-evidence",
            "reaction-clean-report-positive",
            "reaction-clean-explicit-commit",
            "merge-status-report-positive",
            "finding-report-positive",
        }
        self.assertTrue(required.issubset(fixture_ids))
        for fixture in fixtures:
            with self.subTest(fixture=fixture["id"]):
                self.assertEqual(set(fixture), {"id", "base", "patch", "valid"})
                base = self.grammar["report_bases"][fixture["base"]]
                report = _merge_patch(base, fixture["patch"])
                self.assertEqual(
                    self.report_validator.validate(report), fixture["valid"]
                )

    def test_normalization_is_scalar_and_does_not_apply_unicode_normalization(
        self,
    ) -> None:
        self.assertEqual(
            _normalize_body(
                "\talpha\r\nbeta\rgamma\vdelta\fepsilon\u0085zeta\u2028eta\u2029theta \n"
            ),
            "alpha\nbeta\ngamma\ndelta\nepsilon\nzeta\neta\ntheta",
        )
        self.assertNotEqual(_normalize_body("e\u0301"), _normalize_body("é"))
        with self.assertRaises(ValueError):
            _normalize_body("bad\ud800scalar")


if __name__ == "__main__":
    unittest.main()
