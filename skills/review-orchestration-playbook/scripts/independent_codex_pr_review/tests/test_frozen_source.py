from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pathlib
import unittest
from collections.abc import Callable
from typing import Any
from unittest import mock

import review_supervisor.frozen_source as frozen_source_module
from review_supervisor.constants import (
    HELPER_PREFLIGHT_STATUS,
    PRIMARY_DIFF_RELATIVE_PATH,
)
from review_supervisor.frozen_source import (
    FrozenSourceCustody,
    FrozenSourceError,
    authenticate_frozen_source,
)

from tests.support import build_helper_fixture, owned_temporary_directory


JsonObject = dict[str, Any]
Fixture = dict[str, object]


def _read_json(path: pathlib.Path) -> JsonObject:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise AssertionError(f"fixture JSON is not an object: {path}")
    return value


def _write_json(path: pathlib.Path, value: object) -> bytes:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path.write_bytes(raw)
    os.chmod(path, 0o600)
    return raw


def _mutate_json(path: pathlib.Path, mutation: Callable[[JsonObject], None]) -> bytes:
    value = _read_json(path)
    mutation(value)
    return _write_json(path, value)


def _artifact_record(payload: JsonObject, name: str) -> JsonObject:
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        raise AssertionError("fixture artifact list is malformed")
    for candidate in artifacts:
        if isinstance(candidate, dict) and candidate.get("name") == name:
            return candidate
    raise AssertionError(f"fixture artifact is missing: {name}")


def _refresh_control_directory_evidence(fixture: Fixture) -> None:
    workspace = fixture["workspace"]
    state_dir = fixture["state_dir"]
    if not isinstance(workspace, pathlib.Path) or not isinstance(
        state_dir, pathlib.Path
    ):
        raise AssertionError("fixture paths are malformed")
    control = workspace / ".codex-review"
    metadata = os.stat(control, follow_symlinks=False)
    names = set(os.listdir(control))
    names_digest = hashlib.sha256(
        b"\0".join(name.encode("ascii") for name in sorted(names))
    ).hexdigest()

    def refresh(payload: JsonObject) -> None:
        payload["directory"] = {
            "ctime_ns": metadata.st_ctime_ns,
            "device": metadata.st_dev,
            "entry_count": len(names),
            "entry_names_sha256": names_digest,
            "inode": metadata.st_ino,
            "link_count": metadata.st_nlink,
            "mode": metadata.st_mode,
            "mtime_ns": metadata.st_mtime_ns,
            "uid": metadata.st_uid,
        }

    _mutate_json(state_dir / "control-artifact-state.json", refresh)


def _authenticate(
    fixture: Fixture,
    *,
    state_dir: pathlib.Path | None = None,
    repo: pathlib.Path | None = None,
    base_sha: str | None = None,
    head_sha: str | None = None,
) -> FrozenSourceCustody:
    fixture_state = fixture["state_dir"]
    fixture_repo = fixture["repo"]
    fixture_base = fixture["base"]
    fixture_head = fixture["head"]
    if not isinstance(fixture_state, pathlib.Path) or not isinstance(
        fixture_repo, pathlib.Path
    ):
        raise AssertionError("fixture paths are malformed")
    if not isinstance(fixture_base, str) or not isinstance(fixture_head, str):
        raise AssertionError("fixture range is malformed")
    return authenticate_frozen_source(
        state_dir=state_dir or fixture_state,
        repo=repo or fixture_repo,
        base_sha=base_sha or fixture_base,
        head_sha=head_sha or fixture_head,
    )


class FrozenSourceAuthenticationTests(unittest.TestCase):
    def test_authenticates_current_retained_state_contract(self) -> None:
        with owned_temporary_directory("frozen-source-success-") as root:
            fixture = build_helper_fixture(root)
            state_dir = fixture["state_dir"]
            workspace = fixture["workspace"]
            diff = fixture["diff"]
            base = fixture["base"]
            head = fixture["head"]
            self.assertIsInstance(state_dir, pathlib.Path)
            self.assertIsInstance(workspace, pathlib.Path)
            self.assertIsInstance(diff, bytes)
            self.assertIsInstance(base, str)
            self.assertIsInstance(head, str)

            def add_current_state_fields(state: JsonObject) -> None:
                state.update(
                    {
                        "attempts_path": str(state_dir / "attempts.json"),
                        "egress_consent": None,
                        "final_path": str(state_dir / "final.txt"),
                        "pid": 12345,
                        "started_at": 1.0,
                        "stderr_path": str(state_dir / "runner.stderr.log"),
                        "stdout_path": str(state_dir / "runner.stdout.log"),
                        "synthetic_secret_exemptions": [],
                    }
                )

            _mutate_json(state_dir / "state.json", add_current_state_fields)
            preflight_raw = _write_json(
                state_dir / "preflight.json",
                {
                    "primary_diff": {
                        "path": PRIMARY_DIFF_RELATIVE_PATH,
                        "sha256": hashlib.sha256(diff).hexdigest(),
                        "size": len(diff),
                    },
                    "review_range": f"{base}..{head}",
                    "scope": "frozen tracked workspace, diff, and review prompt",
                    "status": HELPER_PREFLIGHT_STATUS,
                    "synthetic_evidence": [],
                },
            )
            control_state = _read_json(state_dir / "control-artifact-state.json")
            control_state["artifacts"] = sorted(
                control_state["artifacts"], key=lambda item: item["name"]
            )
            control_raw = _write_json(
                state_dir / "control-artifact-state.json", control_state
            )

            with _authenticate(fixture) as custody:
                workspace_fd = custody.workspace_fd
                diff_fd = custody.diff_fd
                self.assertEqual(custody.workspace_root, workspace)
                self.assertEqual(custody.review_range, f"{base}..{head}")
                self.assertEqual(custody.diff_size, len(diff))
                self.assertEqual(custody.diff_sha256, hashlib.sha256(diff).hexdigest())
                self.assertEqual(
                    custody.preflight_sha256,
                    hashlib.sha256(preflight_raw).hexdigest(),
                )
                self.assertEqual(
                    custody.control_state_sha256,
                    hashlib.sha256(control_raw).hexdigest(),
                )
                bundle = custody.build_bundle()
                self.assertEqual(len(bundle.artifacts), 1)
                self.assertEqual(bundle.artifacts[0].role, "primary_diff")
                self.assertEqual(bundle.artifacts[0].content.encode(), diff)

            for descriptor in (workspace_fd, diff_fd):
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            custody.close()
            with self.assertRaisesRegex(FrozenSourceError, "custody is closed"):
                custody.build_bundle()
            with self.assertRaisesRegex(FrozenSourceError, "custody is closed"):
                custody.__enter__()

    def test_rejects_non_exact_inputs(self) -> None:
        with owned_temporary_directory("frozen-source-inputs-") as root:
            fixture = build_helper_fixture(root)
            state_dir = fixture["state_dir"]
            repo = fixture["repo"]
            self.assertIsInstance(state_dir, pathlib.Path)
            self.assertIsInstance(repo, pathlib.Path)
            cases = (
                ("relative state", {"state_dir": pathlib.Path("helper-state")}),
                ("relative repo", {"repo": pathlib.Path("repo")}),
                (
                    "dot component",
                    {"state_dir": state_dir / "nested" / ".." / ".."},
                ),
                ("short base", {"base_sha": "a" * 39}),
                ("uppercase head", {"head_sha": "B" * 40}),
            )
            for label, overrides in cases:
                with self.subTest(label=label):
                    with self.assertRaisesRegex(
                        FrozenSourceError, "inputs are not exact absolute values"
                    ):
                        _authenticate(fixture, **overrides)

    def test_rejects_invalid_marker_and_non_retained_state(self) -> None:
        cases: tuple[
            tuple[str, Callable[[Fixture], None], str],
            ...,
        ] = (
            (
                "marker",
                lambda fixture: pathlib.Path(
                    fixture["state_dir"] / ".isolated-review-state"
                ).write_bytes(b"wrong-marker\n"),
                "state marker is invalid",
            ),
            (
                "version",
                lambda fixture: _mutate_json(
                    fixture["state_dir"] / "state.json",
                    lambda state: state.__setitem__("version", 2),
                ),
                "not a retained Codex review",
            ),
            (
                "reviewer",
                lambda fixture: _mutate_json(
                    fixture["state_dir"] / "state.json",
                    lambda state: state.__setitem__("reviewer", "claude"),
                ),
                "not a retained Codex review",
            ),
            (
                "keep workspace",
                lambda fixture: _mutate_json(
                    fixture["state_dir"] / "state.json",
                    lambda state: state.__setitem__("keep_workspace", False),
                ),
                "not a retained Codex review",
            ),
        )
        for label, tamper, message in cases:
            with self.subTest(label=label):
                with owned_temporary_directory(f"frozen-source-{label}-") as root:
                    fixture = build_helper_fixture(root)
                    tamper(fixture)
                    with self.assertRaisesRegex(FrozenSourceError, message):
                        _authenticate(fixture)

    def test_rejects_malformed_workspace_state_and_noncanonical_diff(self) -> None:
        def add_workspace_field(fixture: Fixture) -> None:
            def mutate(state: JsonObject) -> None:
                state["workspace"]["unexpected"] = True

            _mutate_json(fixture["state_dir"] / "state.json", mutate)

        def change_diff_path(fixture: Fixture) -> None:
            def mutate(state: JsonObject) -> None:
                state["workspace"]["diff_file"] = str(
                    fixture["workspace"] / "review.diff"
                )

            _mutate_json(fixture["state_dir"] / "state.json", mutate)

        cases = (
            ("workspace shape", add_workspace_field, "workspace state is malformed"),
            ("diff path", change_diff_path, "diff path is not canonical"),
        )
        for label, tamper, message in cases:
            with self.subTest(label=label):
                with owned_temporary_directory(f"frozen-source-{label}-") as root:
                    fixture = build_helper_fixture(root)
                    tamper(fixture)
                    with self.assertRaisesRegex(FrozenSourceError, message):
                        _authenticate(fixture)

    def test_binds_exact_range_and_repository(self) -> None:
        with owned_temporary_directory("frozen-source-binding-") as root:
            fixture = build_helper_fixture(root)
            other_repo = root / "other-repo"
            other_repo.mkdir(mode=0o700)
            cases = (
                ("base", {"base_sha": "3" * 40}),
                ("head", {"head_sha": "4" * 40}),
                ("repo", {"repo": other_repo}),
            )
            for label, overrides in cases:
                with self.subTest(label=label):
                    with self.assertRaisesRegex(
                        FrozenSourceError, "does not bind the requested source"
                    ):
                        _authenticate(fixture, **overrides)

    def test_requires_completed_runner_and_clean_exit(self) -> None:
        with self.subTest("runner lock"):
            with owned_temporary_directory("frozen-source-running-") as root:
                fixture = build_helper_fixture(root)
                lock_fd = os.open(fixture["state_dir"] / "runner.lock", os.O_RDONLY)
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                try:
                    with self.assertRaises(FrozenSourceError) as raised:
                        _authenticate(fixture)
                    self.assertIsInstance(raised.exception.__cause__, ValueError)
                    self.assertRegex(str(raised.exception.__cause__), "still running")
                finally:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    os.close(lock_fd)

        with self.subTest("malformed exit"):
            with owned_temporary_directory("frozen-source-exit-malformed-") as root:
                fixture = build_helper_fixture(root)
                exit_path = fixture["state_dir"] / "exit-code"
                exit_path.write_bytes(b"not-an-integer\n")
                os.chmod(exit_path, 0o600)
                with self.assertRaises(FrozenSourceError) as raised:
                    _authenticate(fixture)
                self.assertIsInstance(raised.exception.__cause__, ValueError)
                self.assertRegex(
                    str(raised.exception.__cause__), "exit-code is malformed"
                )

        with self.subTest("nonzero exit"):
            with owned_temporary_directory("frozen-source-exit-nonzero-") as root:
                fixture = build_helper_fixture(root)
                exit_path = fixture["state_dir"] / "exit-code"
                exit_path.write_bytes(b"127\n")
                os.chmod(exit_path, 0o600)
                with self.assertRaisesRegex(FrozenSourceError, "did not exit cleanly"):
                    _authenticate(fixture)

    def test_requires_matching_successful_preflight(self) -> None:
        cases = (
            ("status", "status", "failed"),
            ("range", "review_range", f"{'3' * 40}..{'4' * 40}"),
        )
        for label, key, value in cases:
            with self.subTest(label=label):
                with owned_temporary_directory(
                    f"frozen-source-preflight-{label}-"
                ) as root:
                    fixture = build_helper_fixture(root)
                    _mutate_json(
                        fixture["state_dir"] / "preflight.json",
                        lambda preflight, key=key, value=value: preflight.__setitem__(
                            key, value
                        ),
                    )
                    with self.assertRaisesRegex(
                        FrozenSourceError, "preflight does not attest the review range"
                    ):
                        _authenticate(fixture)

    def test_requires_exact_primary_diff_preflight(self) -> None:
        def remove_primary(preflight: JsonObject) -> None:
            preflight.pop("primary_diff")

        def add_primary_field(preflight: JsonObject) -> None:
            preflight["primary_diff"]["unexpected"] = True

        cases: tuple[tuple[str, Callable[[JsonObject], None]], ...] = (
            ("missing", remove_primary),
            (
                "non-object",
                lambda preflight: preflight.__setitem__("primary_diff", None),
            ),
            ("extra field", add_primary_field),
            (
                "path",
                lambda preflight: preflight["primary_diff"].__setitem__(
                    "path", "review.diff"
                ),
            ),
            (
                "boolean size",
                lambda preflight: preflight["primary_diff"].__setitem__("size", True),
            ),
            (
                "digest",
                lambda preflight: preflight["primary_diff"].__setitem__(
                    "sha256", "not-a-digest"
                ),
            ),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                with owned_temporary_directory(
                    f"frozen-source-primary-{label}-"
                ) as root:
                    fixture = build_helper_fixture(root)
                    _mutate_json(fixture["state_dir"] / "preflight.json", mutate)
                    with self.assertRaisesRegex(
                        FrozenSourceError,
                        "primary_diff attestation is malformed",
                    ):
                        _authenticate(fixture)

    def test_cross_binds_preflight_primary_diff_to_control_state(self) -> None:
        cases = (
            ("size", "size", 1),
            ("digest", "sha256", "f" * 64),
        )
        for label, key, delta in cases:
            with self.subTest(label=label):
                with owned_temporary_directory(
                    f"frozen-source-primary-binding-{label}-"
                ) as root:
                    fixture = build_helper_fixture(root)

                    def mutate(preflight: JsonObject) -> None:
                        primary = preflight["primary_diff"]
                        if key == "size":
                            primary[key] += delta
                        else:
                            primary[key] = delta

                    _mutate_json(
                        fixture["state_dir"] / "preflight.json",
                        mutate,
                    )
                    with self.assertRaisesRegex(
                        FrozenSourceError,
                        "preflight and control-state primary diff attestations differ",
                    ):
                        _authenticate(fixture)

    def test_rejects_mixed_a_preflight_b_diff_artifacts(self) -> None:
        with owned_temporary_directory("frozen-source-mixed-artifacts-") as root:
            a_root = root / "a"
            b_root = root / "b"
            a_root.mkdir(mode=0o700)
            b_root.mkdir(mode=0o700)
            fixture_a = build_helper_fixture(a_root)
            fixture_b = build_helper_fixture(b_root)
            diff_a = fixture_a["diff"]
            self.assertIsInstance(diff_a, bytes)
            diff_b = b"x" * len(diff_a)
            diff_path_b = fixture_b["workspace"] / ".codex-review" / "review.diff"
            diff_path_b.write_bytes(diff_b)

            def attest_b(payload: JsonObject) -> None:
                record = _artifact_record(payload, "review.diff")
                record["size"] = len(diff_b)
                record["sha256"] = hashlib.sha256(diff_b).hexdigest()

            _mutate_json(
                fixture_b["state_dir"] / "control-artifact-state.json",
                attest_b,
            )
            _write_json(
                fixture_b["state_dir"] / "preflight.json",
                _read_json(fixture_a["state_dir"] / "preflight.json"),
            )

            with self.assertRaisesRegex(
                FrozenSourceError,
                "preflight and control-state primary diff attestations differ",
            ):
                _authenticate(fixture_b)

    def test_validates_control_artifact_state(self) -> None:
        def wrong_schema(payload: JsonObject) -> None:
            payload["schema_version"] = 3

        def wrong_directory_identity(payload: JsonObject) -> None:
            payload["directory"]["inode"] += 1

        def wrong_directory_entries(payload: JsonObject) -> None:
            payload["directory"]["entry_count"] += 1

        def malformed_digest(payload: JsonObject) -> None:
            _artifact_record(payload, "review.diff")["sha256"] = "not-a-digest"

        cases = (
            ("schema", wrong_schema, "schema is unsupported"),
            (
                "directory identity",
                wrong_directory_identity,
                "no longer matches helper evidence",
            ),
            (
                "directory entries",
                wrong_directory_entries,
                "unexpected entry-name set",
            ),
            ("artifact digest", malformed_digest, "digest is invalid"),
        )
        for label, tamper, cause_message in cases:
            with self.subTest(label=label):
                with owned_temporary_directory(
                    f"frozen-source-control-{label}-"
                ) as root:
                    fixture = build_helper_fixture(root)
                    _mutate_json(
                        fixture["state_dir"] / "control-artifact-state.json", tamper
                    )
                    with self.assertRaises(FrozenSourceError) as raised:
                        _authenticate(fixture)
                    self.assertRegex(str(raised.exception.__cause__), cause_message)

    def test_rejects_workspace_with_git_metadata(self) -> None:
        with owned_temporary_directory("frozen-source-git-metadata-") as root:
            fixture = build_helper_fixture(root)
            git_path = fixture["workspace"] / ".git"
            git_path.write_bytes(b"gitdir: elsewhere\n")
            with self.assertRaisesRegex(FrozenSourceError, "workspace contains .git"):
                _authenticate(fixture)


class FrozenSourceDiffTests(unittest.TestCase):
    def test_opens_diff_nofollow(self) -> None:
        with owned_temporary_directory("frozen-source-diff-link-") as root:
            fixture = build_helper_fixture(root)
            diff_path = fixture["workspace"] / ".codex-review" / "review.diff"
            target = root / "target.diff"
            target.write_bytes(fixture["diff"])
            os.chmod(target, 0o600)
            diff_path.unlink()
            os.symlink(target, diff_path)
            _refresh_control_directory_evidence(fixture)

            with self.assertRaises(FrozenSourceError) as raised:
                _authenticate(fixture)
            self.assertIsInstance(raised.exception.__cause__, OSError)

    def test_enforces_diff_size_bounds_and_attested_length(self) -> None:
        with self.subTest("empty"):
            with owned_temporary_directory("frozen-source-diff-empty-") as root:
                fixture = build_helper_fixture(root)
                diff_path = fixture["workspace"] / ".codex-review" / "review.diff"
                diff_path.write_bytes(b"")

                def attest_empty(payload: JsonObject) -> None:
                    record = _artifact_record(payload, "review.diff")
                    record["size"] = 0
                    record["sha256"] = hashlib.sha256(b"").hexdigest()

                _mutate_json(
                    fixture["state_dir"] / "control-artifact-state.json",
                    attest_empty,
                )
                _mutate_json(
                    fixture["state_dir"] / "preflight.json",
                    lambda preflight: preflight["primary_diff"].update(
                        {
                            "sha256": hashlib.sha256(b"").hexdigest(),
                            "size": 0,
                        }
                    ),
                )
                with self.assertRaisesRegex(
                    FrozenSourceError, "diff exceeds the independent gate bound"
                ):
                    _authenticate(fixture)

        with self.subTest("independent cap"):
            with owned_temporary_directory("frozen-source-diff-cap-") as root:
                fixture = build_helper_fixture(root)
                with mock.patch.object(
                    frozen_source_module,
                    "MAX_EVIDENCE_PRIMARY_BYTES",
                    len(fixture["diff"]) - 1,
                ):
                    with self.assertRaisesRegex(
                        FrozenSourceError, "diff exceeds the independent gate bound"
                    ):
                        _authenticate(fixture)

        with self.subTest("attested length"):
            with owned_temporary_directory("frozen-source-diff-length-") as root:
                fixture = build_helper_fixture(root)
                diff_path = fixture["workspace"] / ".codex-review" / "review.diff"
                diff_path.write_bytes(fixture["diff"] + b"x")
                with self.assertRaises(FrozenSourceError) as raised:
                    _authenticate(fixture)
                self.assertRegex(str(raised.exception.__cause__), "length changed")

    def test_rejects_same_size_diff_hash_mismatch(self) -> None:
        with owned_temporary_directory("frozen-source-diff-hash-") as root:
            fixture = build_helper_fixture(root)
            diff_path = fixture["workspace"] / ".codex-review" / "review.diff"
            diff_path.write_bytes(b"x" * len(fixture["diff"]))
            with self.assertRaisesRegex(
                FrozenSourceError, "diff differs from helper control evidence"
            ):
                _authenticate(fixture)

    def test_bundle_uses_held_diff_after_path_replacement(self) -> None:
        with owned_temporary_directory("frozen-source-held-diff-") as root:
            fixture = build_helper_fixture(root)
            custody = _authenticate(fixture)
            try:
                diff_path = fixture["workspace"] / ".codex-review" / "review.diff"
                diff_path.unlink()
                diff_path.write_bytes(b"replacement evidence\n")
                os.chmod(diff_path, 0o600)

                bundle = custody.build_bundle()
                self.assertEqual(bundle.artifacts[0].content.encode(), fixture["diff"])
            finally:
                custody.close()


class FrozenSourceDescriptorTests(unittest.TestCase):
    def test_authentication_failure_closes_every_opened_descriptor(self) -> None:
        with owned_temporary_directory("frozen-source-close-failure-") as root:
            fixture = build_helper_fixture(root)
            opened: list[int] = []
            real_open_chain = frozen_source_module.open_absolute_directory_chain
            real_open_child = frozen_source_module._open_child_directory
            real_open_regular = frozen_source_module.open_regular_at

            def capture(
                operation: Callable[..., tuple[int, object]],
            ) -> Callable[..., tuple[int, object]]:
                def wrapped(*args: object, **kwargs: object) -> tuple[int, object]:
                    descriptor, identity = operation(*args, **kwargs)
                    opened.append(descriptor)
                    return descriptor, identity

                return wrapped

            with (
                mock.patch.object(
                    frozen_source_module,
                    "open_absolute_directory_chain",
                    side_effect=capture(real_open_chain),
                ),
                mock.patch.object(
                    frozen_source_module,
                    "_open_child_directory",
                    side_effect=capture(real_open_child),
                ),
                mock.patch.object(
                    frozen_source_module,
                    "open_regular_at",
                    side_effect=capture(real_open_regular),
                ),
                mock.patch.object(
                    frozen_source_module,
                    "read_fd_exact",
                    side_effect=OSError("injected diff read failure"),
                ),
            ):
                with self.assertRaisesRegex(
                    FrozenSourceError, "source authentication failed"
                ):
                    _authenticate(fixture)

            self.assertEqual(len(opened), 4)
            for descriptor in opened:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_close_attempts_both_descriptors_after_first_close_failure(self) -> None:
        with owned_temporary_directory("frozen-source-close-all-") as root:
            fixture = build_helper_fixture(root)
            custody = _authenticate(fixture)
            real_close = os.close
            calls: list[int] = []

            def injected_close(descriptor: int) -> None:
                calls.append(descriptor)
                if descriptor == custody.diff_fd:
                    raise OSError("injected close failure")
                real_close(descriptor)

            try:
                with mock.patch.object(
                    frozen_source_module.os,
                    "close",
                    side_effect=injected_close,
                ):
                    with self.assertRaisesRegex(OSError, "injected close failure"):
                        custody.close()

                self.assertEqual(calls, [custody.diff_fd, custody.workspace_fd])
                with self.assertRaises(OSError):
                    os.fstat(custody.workspace_fd)
            finally:
                for descriptor in (custody.diff_fd, custody.workspace_fd):
                    try:
                        real_close(descriptor)
                    except OSError:
                        pass


if __name__ == "__main__":
    unittest.main()
