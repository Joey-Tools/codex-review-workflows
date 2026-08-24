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
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
APP_SLUG = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?\Z")


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

    def __init__(
        self,
        grammar: dict[str, object],
        parent_selection_outcome: dict[str, object],
        direct_positive_parent_scope: dict[str, object],
        terminal_clean_parent_identity: dict[str, object],
        reaction_clean_parent_identity: dict[str, object],
        merge_status_parent_scope: dict[str, object],
        merge_status_parent_contract: dict[str, object],
    ) -> None:
        self.grammar_name = grammar["schema"]
        self.schema = grammar["required_report_schema"]
        self.fields = self.schema["closed_fields"]
        self.parent_input_profiles = self.schema["parent_input_profiles"]
        self.scope_rules = self.schema["scope_rules"]
        self.rules = self.schema["basis_rules"]
        self.finding_rules = self.schema["unresolved_provider_findings_rules"]
        self.parent_selection_outcome = copy.deepcopy(parent_selection_outcome)
        self.direct_positive_parent_scope = copy.deepcopy(direct_positive_parent_scope)
        self.terminal_clean_parent_identity = copy.deepcopy(
            terminal_clean_parent_identity
        )
        self.reaction_clean_parent_identity = copy.deepcopy(
            reaction_clean_parent_identity
        )
        self.merge_status_parent_scope = copy.deepcopy(merge_status_parent_scope)
        self.merge_status_parent_contract = copy.deepcopy(merge_status_parent_contract)

    def _closed(self, value: object, profile: str) -> bool:
        return isinstance(value, dict) and set(value) == set(self.fields[profile])

    def _closed_parent_input(self, value: object, profile: str) -> bool:
        return isinstance(value, dict) and set(value) == set(
            self.parent_input_profiles[profile]
        )

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

    def _selection_outcome_matches(self, report: dict[str, object]) -> bool:
        selection = self.parent_selection_outcome
        rules = self.schema["selection_outcome_rules"]
        if (
            not self._closed_parent_input(selection, "selection_outcome")
            or selection["owner"] != rules["owner"]
            or not isinstance(selection["repository"], str)
            or selection["repository"].count("/") != 1
            or not all(selection["repository"].split("/"))
            or report["repository"] != selection["repository"]
            or report["pull_request"] != selection["pull_request"]
            or report["head_sha"] != selection["head_sha"]
        ):
            return False
        if selection["outcome"] == "selected-pr":
            return self._positive_int(selection["pull_request"]) and self._full_sha(
                selection["head_sha"]
            )
        if selection["outcome"] == "proved-no-selected-supported-pr":
            return selection["pull_request"] is None and selection["head_sha"] is None
        return False

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

    def _clean_terminal_evidence(
        self, report: dict[str, object], evidence: object
    ) -> bool:
        if not self._terminal_evidence(report, evidence):
            return False
        branch_by_channel = {
            "issue-comment": "clean-issue-v1",
            "review": "clean-review-v1",
        }
        return evidence["grammar_branch"] == branch_by_channel.get(
            evidence["channel"]
        ) and self._clean_evidence_url_matches_scope(report, evidence)

    def _direct_positive_scope_matches(self, report: dict[str, object]) -> bool:
        parent_scope = self.direct_positive_parent_scope
        return (
            self._closed_parent_input(parent_scope, "selected_pr_scope")
            and isinstance(parent_scope["repository"], str)
            and parent_scope["repository"].count("/") == 1
            and all(parent_scope["repository"].split("/"))
            and self._positive_int(parent_scope["pull_request"])
            and self._full_sha(parent_scope["head_sha"])
            and report["repository"] == parent_scope["repository"]
            and report["pull_request"] == parent_scope["pull_request"]
            and report["head_sha"] == parent_scope["head_sha"]
        )

    def _direct_terminal_identity_matches(
        self, report: dict[str, object], evidence: dict[str, object]
    ) -> bool:
        parent_identity = self.terminal_clean_parent_identity
        return (
            self._direct_positive_scope_matches(report)
            and self._closed_parent_input(parent_identity, "terminal_clean_identity")
            and parent_identity["kind"] == "terminal-artifact"
            and self._positive_int(parent_identity["id"])
            and isinstance(parent_identity["url"], str)
            and isinstance(parent_identity["channel"], str)
            and parent_identity["channel"] in {"issue-comment", "review"}
            and all(
                evidence[field] == parent_identity[field]
                for field in self.parent_input_profiles["terminal_clean_identity"]
            )
            and self._clean_evidence_url_matches_scope(report, evidence)
        )

    def _direct_reaction_identity_matches(
        self, report: dict[str, object], evidence: dict[str, object]
    ) -> bool:
        parent_identity = self.reaction_clean_parent_identity
        return (
            self._direct_positive_scope_matches(report)
            and self._closed_parent_input(parent_identity, "reaction_clean_identity")
            and parent_identity["kind"] == "reaction"
            and self._positive_int(parent_identity["id"])
            and isinstance(parent_identity["url"], str)
            and parent_identity["channel"] == "reaction"
            and self._positive_int(parent_identity["request_id"])
            and all(
                evidence[field] == parent_identity[field]
                for field in self.parent_input_profiles["reaction_clean_identity"]
            )
            and self._reaction_evidence_url_matches_scope(report, evidence)
        )

    @staticmethod
    def _safe_contract_path(value: object) -> bool:
        if not isinstance(value, str) or not value or "\\" in value:
            return False
        path = pathlib.PurePosixPath(value)
        return (
            not path.is_absolute()
            and path.as_posix() == value
            and all(part not in {"", ".", ".."} for part in path.parts)
        )

    def _merge_status_evidence(
        self, report: dict[str, object], evidence: object
    ) -> bool:
        parent_scope = self.merge_status_parent_scope
        parent_contract = self.merge_status_parent_contract
        if (
            not isinstance(parent_scope, dict)
            or not isinstance(parent_contract, dict)
            or set(parent_scope) != {"repository", "pull_request", "head_sha"}
            or report["repository"] != parent_scope["repository"]
            or report["pull_request"] != parent_scope["pull_request"]
            or report["head_sha"] != parent_scope["head_sha"]
            or set(parent_contract)
            != {
                "contract_descriptor",
                "app_id",
                "app_slug",
                "check_name",
                "check_run_id",
                "check_run_url",
                "provider_clean_evidence_id",
                "provider_clean_evidence_url",
            }
        ):
            return False
        if not self._closed(evidence, "merge_status_evidence"):
            return False
        try:
            completed_at = _time(evidence["server_time"])
        except (TypeError, ValueError):
            return False
        check_name = evidence["check_name"]
        if (
            evidence["kind"] != "merge-status"
            or evidence["channel"] != "check-run"
            or not self._positive_int(evidence["id"])
            or not isinstance(check_name, str)
            or not 1 <= len(check_name) <= 100
            or check_name.strip() != check_name
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in check_name
            )
            or evidence["status"] != "completed"
            or evidence["conclusion"] != "success"
            or not self._full_sha(evidence["artifact_commit"])
            or evidence["artifact_commit"] != report["head_sha"]
            or evidence["server_time_field"] != "completed_at"
            or evidence["head_binding"] != "explicit-commit"
            or evidence["id"] != parent_contract["check_run_id"]
            or evidence["url"] != parent_contract["check_run_url"]
        ):
            return False

        parsed_url = urllib.parse.urlsplit(evidence["url"])
        repository_parts = report["repository"].split("/")
        if (
            parsed_url.scheme != "https"
            or parsed_url.netloc != "github.com"
            or parsed_url.query
            or parsed_url.fragment
            or parsed_url.path.removeprefix("/").split("/")
            != [*repository_parts, "runs", str(evidence["id"])]
        ):
            return False

        app = evidence["app"]
        if (
            not self._closed(app, "merge_status_app")
            or not self._positive_int(app["id"])
            or not isinstance(app["slug"], str)
            or APP_SLUG.fullmatch(app["slug"]) is None
        ):
            return False

        association = evidence["association"]
        if not self._closed(association, "merge_status_association"):
            return False
        contract = association["contract"]
        if not self._closed(contract, "merge_status_contract"):
            return False
        expected_descriptor = parent_contract["contract_descriptor"]
        if not self._closed(expected_descriptor, "merge_status_contract"):
            return False
        source_repository = contract["source_repository"]
        if (
            not isinstance(source_repository, str)
            or source_repository.count("/") != 1
            or any(not part for part in source_repository.split("/"))
            or not self._full_sha(contract["source_commit"])
            or not self._safe_contract_path(contract["source_path"])
            or not isinstance(contract["source_sha256"], str)
            or SHA256.fullmatch(contract["source_sha256"]) is None
        ):
            return False
        descriptor_fields = tuple(self.fields["merge_status_contract"])
        try:
            descriptor_identity = tuple(
                contract[field].encode("utf-8") for field in descriptor_fields
            )
            expected_descriptor_identity = tuple(
                expected_descriptor[field].encode("utf-8")
                for field in descriptor_fields
            )
            app_slug_identity = app["slug"].encode("utf-8")
            expected_app_slug_identity = parent_contract["app_slug"].encode("utf-8")
            check_name_identity = check_name.encode("utf-8")
            expected_check_name_identity = parent_contract["check_name"].encode("utf-8")
        except (AttributeError, UnicodeEncodeError):
            return False
        if (
            descriptor_identity != expected_descriptor_identity
            or app["id"] != parent_contract["app_id"]
            or app_slug_identity != expected_app_slug_identity
            or check_name_identity != expected_check_name_identity
        ):
            return False

        provider_clean = association["provider_clean_evidence"]
        if (
            association["kind"] != "parent-verified-repository-contract"
            or association["owner"] != "parent-orchestrator"
            or association["status"] != "complete"
            or association["repository"] != report["repository"]
            or association["pull_request"] != report["pull_request"]
            or association["head_sha"] != report["head_sha"]
            or association["check_run_id"] != evidence["id"]
            or association["check_run_url"] != evidence["url"]
            or association["check_name"] != check_name
            or association["app_id"] != app["id"]
            or association["app_slug"] != app["slug"]
            or not self._clean_terminal_evidence(report, provider_clean)
            or provider_clean["artifact_commit"] != report["head_sha"]
            or not self._clean_evidence_url_matches_scope(report, provider_clean)
            or provider_clean["id"] != parent_contract["provider_clean_evidence_id"]
            or provider_clean["url"] != parent_contract["provider_clean_evidence_url"]
        ):
            return False
        try:
            provider_clean_time = _time(provider_clean["server_time"])
        except (TypeError, ValueError):
            return False
        return provider_clean_time <= completed_at

    @staticmethod
    def _clean_evidence_url_matches_scope(
        report: dict[str, object], evidence: dict[str, object]
    ) -> bool:
        parsed = urllib.parse.urlsplit(evidence["url"])
        repository_parts = report["repository"].split("/")
        fragment_prefix = {
            "issue-comment": "issuecomment-",
            "review": "pullrequestreview-",
        }.get(evidence["channel"])
        return (
            fragment_prefix is not None
            and parsed.scheme == "https"
            and parsed.netloc == "github.com"
            and not parsed.query
            and parsed.path.removeprefix("/").split("/")
            == [*repository_parts, "pull", str(report["pull_request"])]
            and parsed.fragment == f"{fragment_prefix}{evidence['id']}"
        )

    @staticmethod
    def _reaction_evidence_url_matches_scope(
        report: dict[str, object], evidence: dict[str, object]
    ) -> bool:
        parsed = urllib.parse.urlsplit(evidence["url"])
        repository_parts = report["repository"].split("/")
        return (
            parsed.scheme == "https"
            and parsed.netloc == "github.com"
            and not parsed.query
            and parsed.path.removeprefix("/").split("/")
            == [*repository_parts, "pull", str(report["pull_request"])]
            and parsed.fragment == f"issuecomment-{evidence['request_id']}"
        )

    @staticmethod
    def _finding_url_matches_scope(
        report: dict[str, object],
        evidence: dict[str, object],
        finding: dict[str, object],
    ) -> bool:
        url = finding["url"]
        if not isinstance(url, str):
            return False
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.query:
            return False
        repository_parts = report["repository"].split("/")
        path_parts = parsed.path.removeprefix("/").split("/")
        if path_parts[:2] != repository_parts:
            return False
        branch = finding["grammar_branch"]
        if branch == "top-level-finding-v1":
            fragment_prefix = {
                "issue-comment": "issuecomment-",
                "review": "pullrequestreview-",
            }.get(evidence["channel"])
            return (
                url == evidence["url"]
                and path_parts
                == [*repository_parts, "pull", str(report["pull_request"])]
                and parsed.fragment == f"{fragment_prefix}{finding['id']}"
            )
        return (
            branch == "inline-parent-v1"
            and path_parts
            == [
                *repository_parts,
                "pull",
                str(report["pull_request"]),
            ]
            and parsed.fragment == f"discussion_r{finding['id']}"
        )

    def _unresolved_findings(
        self, report: dict[str, object], evidence: dict[str, object]
    ) -> bool:
        findings = report["unresolved_provider_findings"]
        seen_ids: set[int] = set()
        seen_urls: set[str] = set()
        branches: set[str] = set()
        for finding in findings:
            if not self._closed(finding, "unresolved_provider_finding"):
                return False
            branch = finding["grammar_branch"]
            if (
                not self._positive_int(finding["id"])
                or not isinstance(finding["url"], str)
                or branch not in {"top-level-finding-v1", "inline-parent-v1"}
                or not self._full_sha(finding["artifact_commit"])
                or finding["artifact_commit"] != evidence["artifact_commit"]
                or not self._positive_int(finding["evidence_id"])
                or finding["evidence_id"] != evidence["id"]
                or finding["report_head_sha"] != report["head_sha"]
                or not self._finding_url_matches_scope(report, evidence, finding)
                or finding["id"] in seen_ids
                or finding["url"] in seen_urls
            ):
                return False
            if branch == "top-level-finding-v1":
                if (
                    finding["id"] != evidence["id"]
                    or finding["thread_is_resolved"] is not None
                ):
                    return False
            elif finding["thread_is_resolved"] is not False:
                return False
            seen_ids.add(finding["id"])
            seen_urls.add(finding["url"])
            branches.add(branch)
        evidence_branch = evidence["grammar_branch"]
        return (
            evidence_branch == "inline-parent-v1" and branches == {"inline-parent-v1"}
        ) or (
            evidence_branch == "top-level-finding-v1"
            and "top-level-finding-v1" in branches
        )

    def _selected_pr_scope(self, report: dict[str, object]) -> bool:
        rule = self.scope_rules["selected-pr"]
        return (
            report["status"] in rule["status_values"]
            and self._positive_int(report["pull_request"])
            and self._full_sha(report["head_sha"])
            and report["scope_assurance"] == rule["scope_assurance"]
            and report["base_assurance"] == rule["base_assurance"]
        )

    def _no_selected_supported_pr_scope(self, report: dict[str, object]) -> bool:
        rule = self.scope_rules["no-selected-supported-pr"]
        return (
            report["status"] == rule["status"]
            and report["pull_request"] is rule["pull_request"]
            and report["head_sha"] is rule["head_sha"]
            and report["scope_assurance"] == rule["scope_assurance"]
            and report["base_assurance"] == rule["base_assurance"]
            and report["basis"] is rule["basis"]
            and report["evidence"] is rule["evidence"]
            and report["request_policy"]["status"] == rule["request_policy_status"]
            and not report["request_policy"]["warnings"]
            and not report["unresolved_provider_findings"]
            and report["last_reason"] == rule["last_reason"]
        )

    def validate(self, report: object) -> bool:
        if not self._closed(report, "report"):
            return False
        if (
            report["status"] not in self.schema["status_values"]
            or not isinstance(report["repository"], str)
            or report["repository"].count("/") != 1
            or not isinstance(report["unresolved_provider_findings"], list)
            or not isinstance(report["last_reason"], str)
            or not report["last_reason"]
            or not self._closed(report["request_policy"], "request_policy")
        ):
            return False
        cardinality = self.finding_rules["status_cardinality"][report["status"]]
        if (
            cardinality == "one-or-more" and not report["unresolved_provider_findings"]
        ) or (cardinality == "exactly-zero" and report["unresolved_provider_findings"]):
            return False
        policy = report["request_policy"]
        if (
            policy["status"] not in self.schema["request_policy_status_values"]
            or not isinstance(policy["warnings"], list)
            or not all(isinstance(warning, str) for warning in policy["warnings"])
        ):
            return False
        if not self._selection_outcome_matches(report):
            return False
        if self._no_selected_supported_pr_scope(report):
            return True
        if not self._selected_pr_scope(report):
            return False
        basis = report["basis"]
        evidence = report["evidence"]
        if basis == "terminal-clean":
            rule = self.rules[basis]
            return (
                report["status"] == rule["status"]
                and not report["unresolved_provider_findings"]
                and self._clean_terminal_evidence(report, evidence)
                and self._direct_terminal_identity_matches(report, evidence)
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
                and self._direct_reaction_identity_matches(report, evidence)
            )
        if basis == "merge-status":
            rule = self.rules[basis]
            return (
                report["status"] == rule["status"]
                and not report["unresolved_provider_findings"]
                and self._merge_status_evidence(report, evidence)
                and evidence["kind"] == rule["evidence_kind"]
                and evidence["channel"] == rule["channel"]
                and evidence["status"] == rule["check_status"]
                and evidence["conclusion"] == rule["conclusion"]
                and evidence["artifact_commit"] == report["head_sha"]
                and evidence["head_binding"] == rule["head_binding"]
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
            and self._unresolved_findings(report, evidence)
        )


class GitHubTerminalCarrierContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.grammar = json.loads(GRAMMAR_PATH.read_text(encoding="utf-8"))
        cls.classifier = _ReferenceClassifier(cls.grammar)
        cls.selected_parent_selection_outcome = copy.deepcopy(
            cls.grammar["report_parent_selection_outcomes"]["selected_pr"]
        )
        cls.no_pr_parent_selection_outcome = copy.deepcopy(
            cls.grammar["report_parent_selection_outcomes"][
                "proved_no_selected_supported_pr"
            ]
        )
        cls.direct_positive_parent_scope = {
            "repository": "octo/review-fixture",
            "pull_request": 7,
            "head_sha": "0123456789abcdef0123456789abcdef01234567",
        }
        cls.terminal_clean_parent_identity = {
            "kind": "terminal-artifact",
            "id": 101,
            "url": "https://github.com/octo/review-fixture/pull/7#issuecomment-101",
            "channel": "issue-comment",
        }
        cls.reaction_clean_parent_identity = {
            "kind": "reaction",
            "id": 601,
            "url": "https://github.com/octo/review-fixture/pull/7#issuecomment-91",
            "channel": "reaction",
            "request_id": 91,
        }
        cls.merge_status_parent_scope = {
            "repository": "octo/review-fixture",
            "pull_request": 7,
            "head_sha": "0123456789abcdef0123456789abcdef01234567",
        }
        cls.merge_status_parent_contract = {
            "contract_descriptor": {
                "source_repository": "octo/review-gate",
                "source_commit": "2222222222222222222222222222222222222222",
                "source_path": "contracts/github-codex-merge-status-v1.json",
                "source_sha256": "3333333333333333333333333333333333333333333333333333333333333333",
            },
            "app_id": 15368,
            "app_slug": "github-actions",
            "check_name": "Codex Review Merge Gate",
            "check_run_id": 701,
            "check_run_url": "https://github.com/octo/review-fixture/runs/701",
            "provider_clean_evidence_id": 101,
            "provider_clean_evidence_url": "https://github.com/octo/review-fixture/pull/7#issuecomment-101",
        }
        cls.report_validator = _ReportValidator(
            cls.grammar,
            cls.selected_parent_selection_outcome,
            cls.direct_positive_parent_scope,
            cls.terminal_clean_parent_identity,
            cls.reaction_clean_parent_identity,
            cls.merge_status_parent_scope,
            cls.merge_status_parent_contract,
        )
        cls.no_pr_report_validator = _ReportValidator(
            cls.grammar,
            cls.no_pr_parent_selection_outcome,
            cls.direct_positive_parent_scope,
            cls.terminal_clean_parent_identity,
            cls.reaction_clean_parent_identity,
            cls.merge_status_parent_scope,
            cls.merge_status_parent_contract,
        )

    def _validator_for_selection(
        self, selection_outcome: dict[str, object]
    ) -> _ReportValidator:
        return _ReportValidator(
            self.grammar,
            selection_outcome,
            self.direct_positive_parent_scope,
            self.terminal_clean_parent_identity,
            self.reaction_clean_parent_identity,
            self.merge_status_parent_scope,
            self.merge_status_parent_contract,
        )

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
        self.assertIn(
            "separate closed parent-owned selected-pr scope input",
            report_schema["basis_rules"]["terminal-clean"]["parent_scope_binding"],
        )
        self.assertIn(
            "separate closed parent-owned terminal identity",
            report_schema["basis_rules"]["terminal-clean"]["parent_identity_input"],
        )
        self.assertIn(
            "issuecomment-<evidence-ID>",
            report_schema["basis_rules"]["terminal-clean"]["stable_identity"],
        )
        self.assertIn(
            "pullrequestreview-<evidence-ID>",
            report_schema["basis_rules"]["terminal-clean"]["stable_identity"],
        )
        self.assertEqual(
            report_schema["basis_rules"]["reaction-clean"]["head_binding"],
            "stable-request-epoch",
        )
        self.assertIn(
            "issuecomment-<request-ID>",
            report_schema["basis_rules"]["reaction-clean"]["stable_identity"],
        )
        self.assertEqual(
            report_schema["basis_rules"]["reaction-clean"]["request_relation"],
            "positive request_id equals the parent request comment ID encoded by the URL fragment",
        )
        self.assertIn(
            "separate closed parent-owned selected-pr scope input",
            report_schema["basis_rules"]["reaction-clean"]["parent_scope_binding"],
        )
        self.assertIn(
            "separate closed parent-owned reaction identity",
            report_schema["basis_rules"]["reaction-clean"]["parent_identity_input"],
        )
        self.assertEqual(
            report_schema["parent_input_profiles"],
            {
                "selection_outcome": [
                    "owner",
                    "outcome",
                    "repository",
                    "pull_request",
                    "head_sha",
                ],
                "selected_pr_scope": ["repository", "pull_request", "head_sha"],
                "terminal_clean_identity": ["kind", "id", "url", "channel"],
                "reaction_clean_identity": [
                    "kind",
                    "id",
                    "url",
                    "channel",
                    "request_id",
                ],
            },
        )
        self.assertEqual(
            report_schema["selection_outcome_rules"]["owner"],
            "parent-orchestrator",
        )
        self.assertIn(
            "every report variant",
            report_schema["selection_outcome_rules"]["application"],
        )
        self.assertEqual(
            set(report_schema["selection_outcome_rules"]["outcomes"]),
            {"selected-pr", "proved-no-selected-supported-pr"},
        )
        self.assertEqual(
            report_schema["basis_rules"]["merge-status"]["artifact_commit"],
            "required-full-sha-equals-report-head",
        )
        self.assertEqual(
            report_schema["basis_rules"]["merge-status"]["head_binding"],
            "explicit-commit",
        )
        self.assertEqual(
            report_schema["basis_rules"]["merge-status"]["conclusion"],
            "success",
        )
        self.assertIn(
            "separate closed parent-owned record",
            report_schema["basis_rules"]["merge-status"]["parent_contract_input"],
        )
        self.assertEqual(
            report_schema["basis_rules"]["merge-status"][
                "provider_clean_channel_branch_binding"
            ],
            "issue-comment exactly clean-issue-v1; review exactly clean-review-v1",
        )
        self.assertEqual(
            set(report_schema["closed_fields"]["merge_status_evidence"]),
            {
                "kind",
                "id",
                "url",
                "channel",
                "check_name",
                "status",
                "conclusion",
                "artifact_commit",
                "app",
                "server_time",
                "server_time_field",
                "head_binding",
                "association",
            },
        )
        self.assertEqual(
            set(report_schema["closed_fields"]["merge_status_association"]),
            {
                "kind",
                "owner",
                "status",
                "repository",
                "pull_request",
                "head_sha",
                "check_run_id",
                "check_run_url",
                "check_name",
                "app_id",
                "app_slug",
                "contract",
                "provider_clean_evidence",
            },
        )
        self.assertEqual(
            report_schema["scope_rules"]["selected-pr"]["status_values"],
            ["pass", "findings", "pending", "inconclusive"],
        )
        self.assertEqual(
            report_schema["scope_rules"]["selected-pr"]["parent_selection_outcome"],
            "selected-pr",
        )
        self.assertEqual(
            set(report_schema["closed_fields"]["unresolved_provider_finding"]),
            {
                "id",
                "url",
                "artifact_commit",
                "grammar_branch",
                "thread_is_resolved",
                "evidence_id",
                "report_head_sha",
            },
        )
        self.assertEqual(
            report_schema["unresolved_provider_findings_rules"]["status_cardinality"],
            {
                "pass": "exactly-zero",
                "findings": "one-or-more",
                "pending": "exactly-zero",
                "inconclusive": "exactly-zero",
                "not-applicable": "exactly-zero",
            },
        )
        self.assertEqual(
            report_schema["scope_rules"]["no-selected-supported-pr"],
            {
                "status": "not-applicable",
                "pull_request": None,
                "head_sha": None,
                "scope_assurance": "proved-no-selected-supported-pr",
                "base_assurance": "not-applicable",
                "basis": None,
                "evidence": None,
                "request_policy_status": "not-applicable",
                "request_policy_warnings": "required-empty",
                "unresolved_provider_findings": "required-empty",
                "last_reason": "no-selected-supported-pr",
                "parent_selection_outcome": "proved-no-selected-supported-pr",
            },
        )
        self.assertEqual(
            set(self.grammar["report_base_parent_selection_outcomes"]),
            set(self.grammar["report_bases"]),
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
            "parent-verified-repository-contract",
            "status: completed",
            "conclusion: success",
            "provider_clean_evidence: exact-terminal-clean-evidence-object",
            "independently supplied frozen scope inputs",
            "successful service-start check cannot become a merge-status pass",
            "separate closed\nparent-owned `merge_status_parent_contract` record",
            "exact UTF-8 byte identity",
            "`issue-comment` requires `clean-issue-v1`",
            "`review`\nrequires `clean-review-v1`",
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
            "terminal-clean-cross-repository-url",
            "terminal-clean-cross-pr-url",
            "terminal-clean-cross-evidence-id",
            "terminal-clean-coupled-evidence-id-url-mutation",
            "terminal-clean-coupled-scope-and-id-mutation",
            "terminal-clean-non-https-url",
            "terminal-clean-review-wrong-channel-fragment",
            "terminal-clean-null-artifact-commit",
            "terminal-clean-stable-request-epoch",
            "terminal-clean-artifact-commit-mismatch",
            "terminal-clean-reaction-kind-mismatch",
            "terminal-clean-open-evidence",
            "reaction-clean-report-positive",
            "reaction-clean-cross-repository-url",
            "reaction-clean-cross-pr-url",
            "reaction-clean-request-fragment-mismatch",
            "reaction-clean-request-id-mismatch",
            "reaction-clean-reaction-id-only-mutation",
            "reaction-clean-coupled-identity-mutation",
            "reaction-clean-coupled-scope-and-identity-mutation",
            "reaction-clean-non-https-url",
            "reaction-clean-explicit-commit",
            "merge-status-report-positive",
            "merge-status-null-artifact-commit",
            "merge-status-old-head",
            "merge-status-not-completed",
            "merge-status-unsuccessful-conclusion",
            "merge-status-untrusted-app-id",
            "merge-status-untrusted-app-slug",
            "merge-status-coupled-app-mutation",
            "merge-status-check-run-id-mismatch",
            "merge-status-run-url-mismatch",
            "merge-status-coupled-check-run-identity-mutation",
            "merge-status-check-name-mismatch",
            "merge-status-coupled-check-name-mutation",
            "merge-status-missing-association",
            "merge-status-incomplete-association",
            "merge-status-association-head-mismatch",
            "merge-status-association-repository-mismatch",
            "merge-status-association-pr-mismatch",
            "merge-status-service-start-not-association",
            "merge-status-provider-clean-cross-pr",
            "merge-status-coupled-provider-clean-identity-mutation",
            "merge-status-missing-provider-clean-result",
            "merge-status-stale-provider-clean-result",
            "merge-status-provider-clean-after-check",
            "merge-status-provider-clean-issue-review-branch",
            "merge-status-provider-clean-review-issue-branch",
            "merge-status-invalid-contract-digest",
            "merge-status-coupled-contract-descriptor-mutation",
            "finding-report-positive",
            "inline-finding-report-positive",
            "finding-report-empty-unresolved-list",
            "pending-report-with-unresolved-finding",
            "inconclusive-report-with-unresolved-finding",
            "finding-entry-open-field",
            "finding-entry-evidence-id-mismatch",
            "finding-entry-artifact-commit-mismatch",
            "finding-entry-report-head-mismatch",
            "finding-entry-cross-repository-url",
            "inline-finding-entry-resolved",
            "finding-entry-duplicate-id",
            "finding-entry-duplicate-url",
            "selected-pending-report-positive",
            "selected-inconclusive-report-positive",
            "no-selected-supported-pr-positive",
            "no-pr-null-scope-cannot-pass",
            "no-pr-null-scope-cannot-findings",
            "no-pr-null-scope-cannot-pending",
            "no-pr-null-scope-cannot-inconclusive",
            "no-pr-rejects-non-null-pr",
            "no-pr-rejects-non-null-head",
            "no-pr-rejects-selected-scope-assurance",
            "no-pr-rejects-basis-leak",
            "no-pr-rejects-evidence-leak",
            "selected-pr-rejects-not-applicable",
        }
        self.assertTrue(required.issubset(fixture_ids))
        for fixture in fixtures:
            with self.subTest(fixture=fixture["id"]):
                self.assertEqual(set(fixture), {"id", "base", "patch", "valid"})
                base = self.grammar["report_bases"][fixture["base"]]
                report = _merge_patch(base, fixture["patch"])
                selection_name = self.grammar["report_base_parent_selection_outcomes"][
                    fixture["base"]
                ]
                validator = {
                    "selected_pr": self.report_validator,
                    "proved_no_selected_supported_pr": self.no_pr_report_validator,
                }[selection_name]
                self.assertEqual(validator.validate(report), fixture["valid"])

        terminal_report = copy.deepcopy(self.grammar["report_bases"]["terminal_clean"])
        reaction_report = copy.deepcopy(self.grammar["report_bases"]["reaction_clean"])

        for field, replacement in {
            "repository": "octo/other",
            "pull_request": 8,
            "head_sha": "1111111111111111111111111111111111111111",
        }.items():
            with self.subTest(parent_scope_field=field):
                parent_scope = copy.deepcopy(self.direct_positive_parent_scope)
                parent_scope[field] = replacement
                validator = _ReportValidator(
                    self.grammar,
                    self.selected_parent_selection_outcome,
                    parent_scope,
                    self.terminal_clean_parent_identity,
                    self.reaction_clean_parent_identity,
                    self.merge_status_parent_scope,
                    self.merge_status_parent_contract,
                )
                self.assertFalse(validator.validate(terminal_report))
                self.assertFalse(validator.validate(reaction_report))

        for field, replacement in {
            "kind": "reaction",
            "id": 102,
            "url": "https://github.com/octo/review-fixture/pull/7#issuecomment-102",
            "channel": "review",
        }.items():
            with self.subTest(parent_terminal_identity_field=field):
                parent_identity = copy.deepcopy(self.terminal_clean_parent_identity)
                parent_identity[field] = replacement
                validator = _ReportValidator(
                    self.grammar,
                    self.selected_parent_selection_outcome,
                    self.direct_positive_parent_scope,
                    parent_identity,
                    self.reaction_clean_parent_identity,
                    self.merge_status_parent_scope,
                    self.merge_status_parent_contract,
                )
                self.assertFalse(validator.validate(terminal_report))

        for field, replacement in {
            "kind": "terminal-artifact",
            "id": 602,
            "url": "https://github.com/octo/review-fixture/pull/7#issuecomment-92",
            "channel": "issue-comment",
            "request_id": 92,
        }.items():
            with self.subTest(parent_reaction_identity_field=field):
                parent_identity = copy.deepcopy(self.reaction_clean_parent_identity)
                parent_identity[field] = replacement
                validator = _ReportValidator(
                    self.grammar,
                    self.selected_parent_selection_outcome,
                    self.direct_positive_parent_scope,
                    self.terminal_clean_parent_identity,
                    parent_identity,
                    self.merge_status_parent_scope,
                    self.merge_status_parent_contract,
                )
                self.assertFalse(validator.validate(reaction_report))

        review_url = (
            "https://github.com/octo/review-fixture/pull/7#pullrequestreview-101"
        )
        review_report = _merge_patch(
            terminal_report,
            {
                "evidence": {
                    "url": review_url,
                    "channel": "review",
                    "grammar_branch": "clean-review-v1",
                    "server_time_field": "submitted_at",
                }
            },
        )
        review_parent_identity = {
            "kind": "terminal-artifact",
            "id": 101,
            "url": review_url,
            "channel": "review",
        }
        review_validator = _ReportValidator(
            self.grammar,
            self.selected_parent_selection_outcome,
            self.direct_positive_parent_scope,
            review_parent_identity,
            self.reaction_clean_parent_identity,
            self.merge_status_parent_scope,
            self.merge_status_parent_contract,
        )
        self.assertTrue(review_validator.validate(review_report))

    def test_merge_status_uses_independent_parent_scope_inputs(self) -> None:
        report = copy.deepcopy(self.grammar["report_bases"]["merge_status"])
        self.assertTrue(self.report_validator.validate(report))
        replacements = {
            "repository": "octo/other",
            "pull_request": 8,
            "head_sha": "1111111111111111111111111111111111111111",
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                parent_scope = copy.deepcopy(self.merge_status_parent_scope)
                parent_scope[field] = replacement
                validator = _ReportValidator(
                    self.grammar,
                    self.selected_parent_selection_outcome,
                    self.direct_positive_parent_scope,
                    self.terminal_clean_parent_identity,
                    self.reaction_clean_parent_identity,
                    parent_scope,
                    self.merge_status_parent_contract,
                )
                self.assertFalse(validator.validate(report))

    def test_merge_status_uses_independent_parent_contract_input(self) -> None:
        report = copy.deepcopy(self.grammar["report_bases"]["merge_status"])
        self.assertTrue(self.report_validator.validate(report))
        replacements = {
            "contract_descriptor": {
                "source_repository": "octo/other-gate",
                "source_commit": "4444444444444444444444444444444444444444",
                "source_path": "contracts/other-status-v1.json",
                "source_sha256": "5555555555555555555555555555555555555555555555555555555555555555",
            },
            "app_id": 99999,
            "app_slug": "other-actions",
            "check_name": "Other Review Gate",
            "check_run_id": 702,
            "check_run_url": "https://github.com/octo/review-fixture/runs/702",
            "provider_clean_evidence_id": 102,
            "provider_clean_evidence_url": "https://github.com/octo/review-fixture/pull/7#issuecomment-102",
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                parent_contract = copy.deepcopy(self.merge_status_parent_contract)
                parent_contract[field] = replacement
                validator = _ReportValidator(
                    self.grammar,
                    self.selected_parent_selection_outcome,
                    self.direct_positive_parent_scope,
                    self.terminal_clean_parent_identity,
                    self.reaction_clean_parent_identity,
                    self.merge_status_parent_scope,
                    parent_contract,
                )
                self.assertFalse(validator.validate(report))

    def test_merge_status_provider_clean_channel_branch_pairs_are_closed(
        self,
    ) -> None:
        issue_report = copy.deepcopy(self.grammar["report_bases"]["merge_status"])
        issue_clean = issue_report["evidence"]["association"]["provider_clean_evidence"]
        issue_clean["grammar_branch"] = "clean-review-v1"
        self.assertFalse(self.report_validator.validate(issue_report))

        review_report = copy.deepcopy(self.grammar["report_bases"]["merge_status"])
        review_clean = review_report["evidence"]["association"][
            "provider_clean_evidence"
        ]
        review_url = (
            "https://github.com/octo/review-fixture/pull/7#pullrequestreview-101"
        )
        review_clean.update(
            {
                "url": review_url,
                "channel": "review",
                "grammar_branch": "clean-review-v1",
                "server_time_field": "submitted_at",
            }
        )
        review_parent_contract = copy.deepcopy(self.merge_status_parent_contract)
        review_parent_contract["provider_clean_evidence_url"] = review_url
        review_validator = _ReportValidator(
            self.grammar,
            self.selected_parent_selection_outcome,
            self.direct_positive_parent_scope,
            self.terminal_clean_parent_identity,
            self.reaction_clean_parent_identity,
            self.merge_status_parent_scope,
            review_parent_contract,
        )
        self.assertTrue(review_validator.validate(review_report))
        review_clean["grammar_branch"] = "clean-issue-v1"
        self.assertFalse(review_validator.validate(review_report))

    def test_parent_selection_outcome_binds_every_report_variant(self) -> None:
        selected_reports = [
            copy.deepcopy(self.grammar["report_bases"][base])
            for base in (
                "terminal_clean",
                "reaction_clean",
                "merge_status",
                "finding",
                "inline_finding",
                "selected_pending",
            )
        ]
        inconclusive = copy.deepcopy(self.grammar["report_bases"]["selected_pending"])
        inconclusive["status"] = "inconclusive"
        inconclusive["last_reason"] = "provider-evidence-inconclusive"
        selected_reports.append(inconclusive)

        for report in selected_reports:
            with self.subTest(status=report["status"], basis=report["basis"]):
                self.assertTrue(self.report_validator.validate(report))
                self.assertFalse(self.no_pr_report_validator.validate(report))

        no_pr_report = copy.deepcopy(
            self.grammar["report_bases"]["no_selected_supported_pr"]
        )
        self.assertTrue(self.no_pr_report_validator.validate(no_pr_report))
        self.assertFalse(self.report_validator.validate(no_pr_report))

    def test_parent_selection_outcome_is_closed_and_outcome_discriminated(
        self,
    ) -> None:
        selected_report = copy.deepcopy(
            self.grammar["report_bases"]["selected_pending"]
        )
        no_pr_report = copy.deepcopy(
            self.grammar["report_bases"]["no_selected_supported_pr"]
        )
        malformed_selections = []

        missing_owner = copy.deepcopy(self.selected_parent_selection_outcome)
        missing_owner.pop("owner")
        malformed_selections.append((missing_owner, selected_report))

        extra_field = copy.deepcopy(self.selected_parent_selection_outcome)
        extra_field["source"] = "report"
        malformed_selections.append((extra_field, selected_report))

        wrong_owner = copy.deepcopy(self.selected_parent_selection_outcome)
        wrong_owner["owner"] = "consumer"
        malformed_selections.append((wrong_owner, selected_report))

        selected_shape_with_no_pr_outcome = copy.deepcopy(
            self.selected_parent_selection_outcome
        )
        selected_shape_with_no_pr_outcome["outcome"] = "proved-no-selected-supported-pr"
        malformed_selections.append(
            (selected_shape_with_no_pr_outcome, selected_report)
        )

        no_pr_shape_with_selected_outcome = copy.deepcopy(
            self.no_pr_parent_selection_outcome
        )
        no_pr_shape_with_selected_outcome["outcome"] = "selected-pr"
        malformed_selections.append((no_pr_shape_with_selected_outcome, no_pr_report))

        for selection, report in malformed_selections:
            with self.subTest(selection=selection):
                self.assertFalse(
                    self._validator_for_selection(selection).validate(report)
                )

    def test_parent_selection_outcome_rejects_coupled_report_scope_mutations(
        self,
    ) -> None:
        other_head = "1111111111111111111111111111111111111111"
        selected_pending = copy.deepcopy(
            self.grammar["report_bases"]["selected_pending"]
        )
        for field, replacement in {
            "repository": "octo/other",
            "pull_request": 8,
            "head_sha": other_head,
        }.items():
            with self.subTest(single_field_mismatch=field):
                mismatched = copy.deepcopy(selected_pending)
                mismatched[field] = replacement
                self.assertFalse(self.report_validator.validate(mismatched))

        coupled_pending = copy.deepcopy(selected_pending)
        coupled_pending.update(
            {
                "repository": "octo/other",
                "pull_request": 8,
                "head_sha": other_head,
            }
        )
        coupled_inconclusive = copy.deepcopy(coupled_pending)
        coupled_inconclusive["status"] = "inconclusive"
        coupled_inconclusive["last_reason"] = "provider-evidence-inconclusive"

        coupled_finding = copy.deepcopy(self.grammar["report_bases"]["finding"])
        coupled_finding.update(
            {
                "repository": "octo/other",
                "pull_request": 8,
                "head_sha": other_head,
            }
        )
        coupled_finding["evidence"]["url"] = (
            "https://github.com/octo/other/pull/8#pullrequestreview-301"
        )
        coupled_finding["unresolved_provider_findings"][0].update(
            {
                "url": "https://github.com/octo/other/pull/8#pullrequestreview-301",
                "report_head_sha": other_head,
            }
        )

        other_selected = copy.deepcopy(self.selected_parent_selection_outcome)
        other_selected.update(
            {
                "repository": "octo/other",
                "pull_request": 8,
                "head_sha": other_head,
            }
        )
        other_selected_validator = self._validator_for_selection(other_selected)
        for report in (coupled_pending, coupled_inconclusive, coupled_finding):
            with self.subTest(status=report["status"]):
                self.assertTrue(other_selected_validator.validate(report))
                self.assertFalse(self.report_validator.validate(report))

        coupled_no_pr = copy.deepcopy(
            self.grammar["report_bases"]["no_selected_supported_pr"]
        )
        coupled_no_pr["repository"] = "octo/other"
        other_no_pr = copy.deepcopy(self.no_pr_parent_selection_outcome)
        other_no_pr["repository"] = "octo/other"
        self.assertTrue(
            self._validator_for_selection(other_no_pr).validate(coupled_no_pr)
        )
        self.assertFalse(self.no_pr_report_validator.validate(coupled_no_pr))

    def test_selected_pr_report_variants_reject_present_null_scope(self) -> None:
        selected_reports = [
            copy.deepcopy(self.grammar["report_bases"][base])
            for base in (
                "terminal_clean",
                "reaction_clean",
                "merge_status",
                "finding",
                "selected_pending",
            )
        ]
        inconclusive = copy.deepcopy(self.grammar["report_bases"]["selected_pending"])
        inconclusive["status"] = "inconclusive"
        inconclusive["last_reason"] = "provider-evidence-inconclusive"
        selected_reports.append(inconclusive)
        for report in selected_reports:
            for field in ("pull_request", "head_sha"):
                with self.subTest(status=report["status"], field=field):
                    null_scope = copy.deepcopy(report)
                    null_scope[field] = None
                    self.assertFalse(self.report_validator.validate(null_scope))

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
