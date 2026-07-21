from __future__ import annotations

import json
import os
import pathlib
import signal
import subprocess
import sys
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

import review_supervisor.gitraw as gitraw

from review_supervisor.checkout import (
    RawMaterializer,
    probe_name_semantics,
    read_and_validate_symlink_graphs,
    validate_namespaces,
)
from review_supervisor.constants import (
    LOW_LEVEL_HELPER_REVIEW_CONTRACT,
    MAX_SYMLINK_BYTES,
    NAMED_LANE_ELIGIBLE,
    SCHEMA_VERSION,
)
from review_supervisor.errors import SupervisorError
from review_supervisor.gitraw import (
    CatFileBatch,
    RepositoryInfo,
    _parse_tree_record,
    add_detached_worktree,
    check_attributes,
    enumerate_tree,
    enumerate_registration,
    initialize_index,
    inspect_repository,
    object_digest,
    remove_both_present_worktree,
    sanitized_git_environment,
    verify_worktree_absent,
)
from review_supervisor.ledger import acquire_retention_lease, read_attempt_state
from review_supervisor.models import HelperCustody, TreeEntry
from review_supervisor.process import (
    process_start_identity,
    signal_anchored_group,
    wait_terminal,
)
from review_supervisor.runtime import _cleanup_worktree, _registration_json
from review_supervisor.secureio import (
    canonical_json,
    identity_from_stat,
    rename_exchange,
    sha256_bytes,
)

from tests.support import build_helper_fixture, owned_temporary_directory


GIT = pathlib.Path("/usr/bin/git")


def _git(repo: pathlib.Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        (str(GIT), "-C", str(repo), *arguments),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
        env=sanitized_git_environment(),
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode("utf-8", "replace"))
    return completed.stdout.strip()


def _init_repository(
    repo: pathlib.Path, *, object_format: str
) -> subprocess.CompletedProcess[bytes]:
    arguments = [str(GIT), "init", "-q"]
    if object_format != "sha1":
        arguments.append(f"--object-format={object_format}")
    arguments.append(str(repo))
    return subprocess.run(
        arguments,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        env=sanitized_git_environment(),
    )


def _build_repository(
    root: pathlib.Path,
    *,
    object_format: str = "sha1",
) -> tuple[pathlib.Path, str, str]:
    repo = root / "repo"
    repo.mkdir(mode=0o700)
    initialized = _init_repository(repo, object_format=object_format)
    if initialized.returncode != 0:
        raise AssertionError(initialized.stderr.decode("utf-8", "replace"))
    _git(repo, "config", "user.name", "Fixture")
    _git(repo, "config", "user.email", "fixture@example.invalid")
    (repo / "base.txt").write_bytes(b"base\n")
    _git(repo, "add", "--", "base.txt")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD").decode("ascii")

    (repo / "nested").mkdir()
    (repo / "nested" / "data.txt").write_bytes(b"raw object bytes\n")
    executable = repo / "tool.sh"
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    (repo / ".gitattributes").write_bytes(b"*.txt -filter -working-tree-encoding\n")
    os.symlink("nested/data.txt", repo / "data-link")
    _git(
        repo,
        "add",
        "--",
        ".gitattributes",
        "nested/data.txt",
        "tool.sh",
        "data-link",
    )
    _git(repo, "commit", "-q", "-m", "head")
    head = _git(repo, "rev-parse", "HEAD").decode("ascii")
    return repo, base, head


def _protocol_batch(response: bytes) -> tuple[CatFileBatch, int]:
    request_reader, request_writer = os.pipe()
    stdout_reader, stdout_writer = os.pipe()
    stderr_reader, stderr_writer = os.pipe()
    if os.write(stdout_writer, response) != len(response):
        raise AssertionError("protocol fixture response write was partial")
    os.close(stdout_writer)
    os.close(stderr_writer)
    batch = CatFileBatch.__new__(CatFileBatch)
    batch.info = RepositoryInfo(
        repo=pathlib.Path("/unused/repo"),
        common_git_dir=pathlib.Path("/unused/repo/.git"),
        object_format="sha1",
        object_hex_length=40,
        base_sha="1" * 40,
        head_sha="2" * 40,
        git_executable=str(GIT),
    )
    batch.process = SimpleNamespace(
        stdin=os.fdopen(request_writer, "wb", buffering=0),
        stdout=os.fdopen(stdout_reader, "rb", buffering=0),
        stderr=os.fdopen(stderr_reader, "rb", buffering=0),
        poll=lambda: 0,
        returncode=0,
    )
    batch.process_group = None
    batch.group_anchor = None
    batch.requests = 0
    batch.closed = False
    batch.stderr = bytearray()
    return batch, request_reader


def _close_protocol_batch(batch: CatFileBatch, request_reader: int) -> None:
    for stream in (
        batch.process.stdin,
        batch.process.stdout,
        batch.process.stderr,
    ):
        if not stream.closed:
            stream.close()
    os.close(request_reader)


def _scripted_batch(root: pathlib.Path, script: bytes) -> CatFileBatch:
    repo = root / "repo"
    repo.mkdir(mode=0o700)
    executable = root / "fake-git"
    executable.write_bytes(script)
    executable.chmod(0o700)
    return CatFileBatch(
        RepositoryInfo(
            repo=repo,
            common_git_dir=repo / ".git",
            object_format="sha1",
            object_hex_length=40,
            base_sha="1" * 40,
            head_sha="2" * 40,
            git_executable=str(executable),
        )
    )


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_process_exit(pid: int, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while _process_exists(pid):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))
    return True


def _force_cleanup_batch(batch: CatFileBatch) -> None:
    group_anchor = getattr(batch, "group_anchor", None)
    if group_anchor is not None:
        try:
            signal_anchored_group(group_anchor, signal.SIGKILL)
        except (ChildProcessError, PermissionError):
            pass
    try:
        batch.process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    for stream in (
        batch.process.stdin,
        batch.process.stdout,
        batch.process.stderr,
    ):
        if stream is not None and not stream.closed:
            stream.close()


def _kill_verified_process(pid: int, start_identity: str) -> None:
    try:
        current_identity = process_start_identity(pid)
    except (OSError, ValueError):
        return
    if current_identity != start_identity:
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


class RawGitProtocolTests(unittest.TestCase):
    def test_tree_parser_enforces_symlink_target_size_limit(self) -> None:
        object_id = b"a" * 40
        accepted = _parse_tree_record(
            b"120000 blob "
            + object_id
            + b" "
            + str(MAX_SYMLINK_BYTES).encode("ascii")
            + b"\tlink",
            object_width=40,
        )
        self.assertEqual(accepted.size, MAX_SYMLINK_BYTES)

        with self.assertRaisesRegex(ValueError, "per-object limit"):
            _parse_tree_record(
                b"120000 blob "
                + object_id
                + b" "
                + str(MAX_SYMLINK_BYTES + 1).encode("ascii")
                + b"\tlink",
                object_width=40,
            )

    def test_cat_file_accepts_exact_blob_protocol(self) -> None:
        payload = b"payload"
        object_id = object_digest("sha1", payload)
        entry = TreeEntry(0o100644, "blob", object_id, len(payload), b"file")
        response = f"{object_id} blob {len(payload)}\n".encode() + payload + b"\n"
        batch, request_reader = _protocol_batch(response)
        try:
            captured = batch.read_blob(entry, capture=True)
            request = os.read(request_reader, 4096)
        finally:
            _close_protocol_batch(batch, request_reader)

        self.assertEqual(captured, payload)
        self.assertEqual(batch.requests, 1)
        self.assertEqual(request, object_id.encode("ascii") + b"\n")

    def test_cat_file_close_is_bounded_on_output_and_open_pipes(self) -> None:
        scripts = (
            (
                "stderr-overflow",
                b"#!/bin/sh\nexec /usr/bin/head -c 4194304 /dev/zero >&2\n",
                OverflowError,
                2.0,
            ),
            (
                "open-pipes",
                b"#!/bin/sh\nexec /bin/sleep 30\n",
                TimeoutError,
                0.25,
            ),
            ("unexpected-stdout", b"#!/bin/sh\nprintf x\n", None, 2.0),
        )
        for label, script, expected_cause, close_timeout in scripts:
            with self.subTest(shutdown_case=label):
                with owned_temporary_directory("git-cat-file-close-") as root:
                    live_batch = _scripted_batch(root, script)
                    errors: list[BaseException] = []
                    worker: threading.Thread | None = None

                    def close_batch() -> None:
                        try:
                            live_batch.close()
                        except BaseException as error:
                            errors.append(error)

                    try:
                        with mock.patch(
                            "review_supervisor.gitraw.CAT_FILE_CLOSE_TIMEOUT_SECONDS",
                            close_timeout,
                        ):
                            worker = threading.Thread(
                                target=close_batch,
                                daemon=True,
                            )
                            worker.start()
                            worker.join(timeout=4)
                        blocked = worker.is_alive()
                        self.assertFalse(
                            blocked,
                            "cat-file shutdown blocked on one pipe",
                        )
                        self.assertFalse(worker.is_alive())
                        self.assertEqual(len(errors), 1)
                        self.assertIsInstance(errors[0], ValueError)
                        self.assertIsNotNone(live_batch.process.poll())
                        for stream in (
                            live_batch.process.stdin,
                            live_batch.process.stdout,
                            live_batch.process.stderr,
                        ):
                            self.assertIsNotNone(stream)
                            self.assertTrue(stream.closed)
                        if expected_cause is None:
                            self.assertIsNone(errors[0].__cause__)
                        else:
                            self.assertIsInstance(
                                errors[0].__cause__,
                                expected_cause,
                            )
                    finally:
                        _force_cleanup_batch(live_batch)
                        if worker is not None and worker.is_alive():
                            worker.join(timeout=2)

        with owned_temporary_directory("git-cat-file-anchor-failure-") as root:
            cleaned: list[subprocess.Popen[bytes]] = []
            abort_session = gitraw._abort_unanchored_fresh_session

            def record_abort(process: subprocess.Popen[bytes]) -> None:
                cleaned.append(process)
                abort_session(process)

            with (
                mock.patch.object(
                    gitraw,
                    "process_start_identity",
                    side_effect=RuntimeError("synthetic identity failure"),
                ),
                mock.patch.object(
                    gitraw,
                    "_abort_unanchored_fresh_session",
                    side_effect=record_abort,
                ),
                self.assertRaisesRegex(RuntimeError, "identity failure"),
            ):
                _scripted_batch(root, b"#!/bin/sh\nexec /bin/sleep 30\n")

            self.assertEqual(len(cleaned), 1)
            self.assertIsNotNone(cleaned[0].returncode)
            for stream in (
                cleaned[0].stdin,
                cleaned[0].stdout,
                cleaned[0].stderr,
            ):
                self.assertIsNotNone(stream)
                self.assertTrue(stream.closed)

    def test_cat_file_read_is_bounded_on_stderr_flood_and_open_pipes(self) -> None:
        payload = b"payload"
        object_id = object_digest("sha1", payload)
        entry = TreeEntry(0o100644, "blob", object_id, len(payload), b"file")
        scripts = (
            (
                "stderr-overflow",
                b"#!/bin/sh\nIFS= read -r request\n"
                b"/usr/bin/head -c 4194304 /dev/zero >&2\n",
                OverflowError,
                1.0,
            ),
            (
                "open-pipes",
                b"#!/bin/sh\nIFS= read -r request\nexec /bin/sleep 30\n",
                TimeoutError,
                0.25,
            ),
        )
        for label, script, expected_error, read_timeout in scripts:
            with self.subTest(read_case=label):
                with owned_temporary_directory("git-cat-file-read-") as root:
                    live_batch = _scripted_batch(root, script)
                    self.assertEqual(
                        os.getpgid(live_batch.process.pid),
                        live_batch.process_group,
                    )
                    self.assertEqual(
                        os.getsid(live_batch.process.pid),
                        live_batch.process.pid,
                    )
                    errors: list[BaseException] = []
                    worker: threading.Thread | None = None

                    def read_blob() -> None:
                        try:
                            live_batch.read_blob(entry, capture=True)
                        except BaseException as error:
                            errors.append(error)

                    try:
                        started = time.monotonic()
                        with mock.patch(
                            "review_supervisor.gitraw.CAT_FILE_READ_TIMEOUT_SECONDS",
                            read_timeout,
                        ):
                            worker = threading.Thread(
                                target=read_blob,
                                daemon=True,
                            )
                            worker.start()
                            worker.join(timeout=4)
                        elapsed = time.monotonic() - started
                        blocked = worker.is_alive()

                        self.assertFalse(
                            blocked,
                            "cat-file read blocked on one pipe",
                        )
                        self.assertFalse(worker.is_alive())
                        self.assertLess(elapsed, 4)
                        self.assertEqual(len(errors), 1)
                        self.assertIsInstance(errors[0], expected_error)
                        self.assertTrue(live_batch.closed)
                        self.assertIsNotNone(live_batch.process.poll())
                        for stream in (
                            live_batch.process.stdin,
                            live_batch.process.stdout,
                            live_batch.process.stderr,
                        ):
                            self.assertIsNotNone(stream)
                            self.assertTrue(stream.closed)
                    finally:
                        _force_cleanup_batch(live_batch)
                        if worker is not None and worker.is_alive():
                            worker.join(timeout=2)

    def test_cat_file_close_terminates_descendant_after_leader_exit(self) -> None:
        script = (
            b"#!/bin/sh\n"
            b"(trap '' TERM; exec /bin/sleep 30) &\n"
            b'printf \'%s\\n\' "$!" > "$0.child-pid"\n'
            b"exit 0\n"
        )
        with owned_temporary_directory("git-cat-file-descendant-") as root:
            live_batch = _scripted_batch(root, script)
            pid_path = root / "fake-git.child-pid"
            descendant_pid: int | None = None
            descendant_identity: str | None = None
            worker: threading.Thread | None = None
            try:
                deadline = time.monotonic() + 2
                while not pid_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(
                    pid_path.exists(),
                    "background child PID was not recorded",
                )
                descendant_pid = int(pid_path.read_text(encoding="ascii").strip())
                descendant_identity = process_start_identity(descendant_pid)
                wait_terminal(
                    live_batch.process.pid,
                    deadline=time.monotonic() + 2,
                )
                self.assertEqual(
                    os.getpgid(descendant_pid),
                    live_batch.process_group,
                )
                self.assertTrue(_process_exists(descendant_pid))
                errors: list[BaseException] = []

                def close_batch() -> None:
                    try:
                        live_batch.close()
                    except BaseException as error:
                        errors.append(error)

                started = time.monotonic()
                with mock.patch(
                    "review_supervisor.gitraw.CAT_FILE_CLOSE_TIMEOUT_SECONDS",
                    0.25,
                ):
                    worker = threading.Thread(target=close_batch, daemon=True)
                    worker.start()
                    worker.join(timeout=4)
                elapsed = time.monotonic() - started
                blocked = worker.is_alive()

                self.assertFalse(blocked, "cat-file descendant kept close blocked")
                self.assertFalse(worker.is_alive())
                self.assertLess(elapsed, 4)
                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], ValueError)
                self.assertIsInstance(errors[0].__cause__, TimeoutError)
                self.assertTrue(
                    _wait_for_process_exit(descendant_pid, timeout=2),
                    "cat-file background descendant survived group termination",
                )
            finally:
                _force_cleanup_batch(live_batch)
                if descendant_pid is not None and descendant_identity is not None:
                    _kill_verified_process(descendant_pid, descendant_identity)
                if worker is not None and worker.is_alive():
                    worker.join(timeout=2)

    def test_cat_file_close_terminates_descendant_that_closed_its_pipes(self) -> None:
        script = (
            b"#!/bin/sh\n"
            b"/bin/sleep 30 </dev/null >/dev/null 2>&1 &\n"
            b'printf \'%s\\n\' "$!" > "$0.child-pid"\n'
            b"exit 0\n"
        )
        with owned_temporary_directory("git-cat-file-detached-descendant-") as root:
            live_batch = _scripted_batch(root, script)
            pid_path = root / "fake-git.child-pid"
            descendant_pid: int | None = None
            descendant_identity: str | None = None
            try:
                deadline = time.monotonic() + 2
                while not pid_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(
                    pid_path.exists(),
                    "background child PID was not recorded",
                )
                descendant_pid = int(pid_path.read_text(encoding="ascii").strip())
                descendant_identity = process_start_identity(descendant_pid)
                wait_terminal(
                    live_batch.process.pid,
                    deadline=time.monotonic() + 2,
                )
                self.assertEqual(
                    os.getpgid(descendant_pid),
                    live_batch.process_group,
                )
                self.assertTrue(_process_exists(descendant_pid))

                started = time.monotonic()
                live_batch.close()
                self.assertLess(time.monotonic() - started, 2)
                self.assertTrue(
                    _wait_for_process_exit(descendant_pid, timeout=2),
                    "cat-file detached descendant survived normal close",
                )
                self.assertFalse(_process_group_exists(live_batch.process_group))
            finally:
                _force_cleanup_batch(live_batch)
                if descendant_pid is not None and descendant_identity is not None:
                    _kill_verified_process(descendant_pid, descendant_identity)

    def test_cat_file_rejects_oid_type_and_length_header_mismatches(self) -> None:
        payload = b"payload"
        object_id = object_digest("sha1", payload)
        entry = TreeEntry(0o100644, "blob", object_id, len(payload), b"file")
        headers = (
            f"{'0' * 40} blob {len(payload)}",
            f"{object_id} tree {len(payload)}",
            f"{object_id} blob {len(payload) + 1}",
        )
        for header in headers:
            with self.subTest(header=header):
                batch, request_reader = _protocol_batch(
                    header.encode() + b"\n" + payload + b"\n"
                )
                try:
                    with self.assertRaisesRegex(ValueError, "header mismatch"):
                        batch.read_blob(entry, capture=True)
                finally:
                    _close_protocol_batch(batch, request_reader)

    def test_cat_file_rejects_payload_length_delimiter_and_digest_mismatches(
        self,
    ) -> None:
        payload = b"payload"
        object_id = object_digest("sha1", payload)
        entry = TreeEntry(0o100644, "blob", object_id, len(payload), b"file")
        header = f"{object_id} blob {len(payload)}\n".encode()
        bad_digest_id = "0" * 40
        cases = (
            (header + payload[:-1], entry, "payload ended early"),
            (header + payload + b"\0", entry, "delimiter is invalid"),
            (
                f"{bad_digest_id} blob {len(payload)}\n".encode() + payload + b"\n",
                TreeEntry(
                    0o100644,
                    "blob",
                    bad_digest_id,
                    len(payload),
                    b"file",
                ),
                "digest mismatch",
            ),
        )
        for response, candidate, message in cases:
            with self.subTest(message=message):
                batch, request_reader = _protocol_batch(response)
                try:
                    with self.assertRaisesRegex(ValueError, message):
                        batch.read_blob(candidate, capture=True)
                finally:
                    _close_protocol_batch(batch, request_reader)


@unittest.skipUnless(GIT.is_file(), "/usr/bin/git is required")
class RawGitCheckoutTests(unittest.TestCase):
    def test_check_attributes_accepts_many_short_unspecified_paths(self) -> None:
        paths = tuple(f"p{index:03d}".encode("ascii") for index in range(200))
        output = b"".join(
            (
                path
                + b"\0filter\0unspecified\0"
                + path
                + b"\0working-tree-encoding\0unspecified\0"
            )
            for path in paths
        )
        info = SimpleNamespace(
            git_executable=str(GIT),
            common_git_dir=pathlib.Path("/repo/.git"),
        )
        registration = SimpleNamespace(
            registration=pathlib.Path("/repo/.git/worktrees/review"),
            worktree=pathlib.Path("/repo/review"),
        )

        def run_with_limit(
            *_args: object,
            **kwargs: object,
        ) -> tuple[int, bytes, bytes]:
            self.assertEqual(kwargs["stdout_limit"], len(output))
            return 0, output, b""

        with mock.patch(
            "review_supervisor.gitraw.run_bounded",
            side_effect=run_with_limit,
        ):
            check_attributes(
                info,
                registration,
                pathlib.Path("/repo/sanitized-view"),
                paths,
            )

    def test_runtime_cleanup_keeps_parent_descriptors_and_settles_exactly(self) -> None:
        with owned_temporary_directory("git-cleanup-") as root:
            repo, base_sha, head_sha = _build_repository(root)
            info = inspect_repository(
                repo=repo,
                base_sha=base_sha,
                head_sha=head_sha,
                git_executable=str(GIT),
            )
            checkout_parent = root / "checkouts"
            checkout_parent.mkdir(mode=0o700)
            worktree = checkout_parent / "review-fixture"
            registration = add_detached_worktree(info, worktree)
            namespace = checkout_parent / ".review-control-fixture"
            namespace.mkdir(mode=0o700)
            retention = root / "retention"
            retention.mkdir(mode=0o700)
            attempt_id = f"1-{'d' * 32}"
            attempt = retention / f"attempt-{attempt_id}"
            attempt.mkdir(mode=0o700)
            try:
                initialize_index(info, registration)
                post_index_count, post_index_path_bytes = enumerate_registration(
                    registration.registration
                )
                self.assertGreaterEqual(post_index_count, registration.descendant_count)
                registration_value = _registration_json(registration)
                registration_value["descendant_count"] = post_index_count
                registration_value["descendant_path_bytes"] = post_index_path_bytes
                state = {
                    "schema_version": SCHEMA_VERSION,
                    "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
                    "named_lane_eligible": NAMED_LANE_ELIGIBLE,
                    "attempt_id": attempt_id,
                    "record_generation": 1,
                    "previous_record_sha256": None,
                    "phase": "reviewed",
                    "repo": str(repo),
                    "base_sha": base_sha,
                    "head_sha": head_sha,
                    "git_executable": str(GIT),
                    "worktree_path": str(worktree),
                    "control_namespace": str(namespace),
                    "registration": registration_value,
                    "worktree_status": "active",
                    "checkout_settlement": "outstanding",
                    "checkout_physical_remaining_by_fs": {"fixture": 1},
                    "cleanup_status": "clean",
                    "checkout_parent_binding": {
                        "path": str(checkout_parent),
                        "identity": identity_from_stat(
                            os.stat(checkout_parent)
                        ).to_json(),
                    },
                    "common_git_dir_binding": {
                        "path": str(info.common_git_dir),
                        "identity": identity_from_stat(
                            os.stat(info.common_git_dir)
                        ).to_json(),
                    },
                }
                state_path = attempt / "state.json"
                state_path.write_bytes(canonical_json(state))
                state_path.chmod(0o600)
                state, _, digest = read_attempt_state(attempt)
                with acquire_retention_lease(
                    retention,
                    deadline=time.monotonic() + 5,
                ) as lease:
                    state, _ = _cleanup_worktree(
                        entrypoint=pathlib.Path(__file__).resolve().parent.parent
                        / "independent-codex-pr-review",
                        attempt_dir=attempt,
                        lease_fd=lease.fd,
                        state=state,
                        state_digest=digest,
                    )
                self.assertEqual(state["checkout_settlement"], "exact")
                self.assertEqual(state["worktree_status"], "removed")
                self.assertFalse(worktree.exists())
                self.assertFalse(registration.registration.exists())
                self.assertFalse(namespace.exists())
                self.assertIsNone(state["retained_worktree"])
                self.assertTrue(
                    state["checkout_cleanup_evidence"]["exact_names_absent"]
                )
                self.assertEqual(
                    state["checkout_cleanup_evidence"]["branch"],
                    "both-present",
                )
            finally:
                if worktree.exists() and registration.registration.exists():
                    remove_both_present_worktree(info, registration)

    def test_cli_preflight_authenticates_without_creating_attempt(self) -> None:
        with owned_temporary_directory("preflight-") as root:
            repo, base_sha, head_sha = _build_repository(root)
            fixture = build_helper_fixture(
                root,
                source_repo=repo,
                base_sha=base_sha,
                head_sha=head_sha,
            )
            retention = root / "retention"
            checkouts = root / "checkouts"
            entrypoint = (
                pathlib.Path(__file__).resolve().parent.parent
                / "independent-codex-pr-review"
            )
            completed = subprocess.run(
                (
                    sys.executable,
                    str(entrypoint),
                    "preflight",
                    "--helper-state",
                    str(fixture["state_dir"]),
                    "--repo",
                    str(repo),
                    "--base",
                    base_sha,
                    "--head",
                    head_sha,
                    "--pr-url",
                    "https://github.example/owner/repo/pull/1",
                    "--retention-root",
                    str(retention),
                    "--checkout-parent",
                    str(checkouts),
                    "--codex",
                    "/usr/bin/true",
                ),
                cwd=pathlib.Path(__file__).resolve().parent.parent,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(
                completed.returncode, 0, completed.stdout + completed.stderr
            )
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["status"], "ready")
            self.assertEqual(
                payload["review_contract"], LOW_LEVEL_HELPER_REVIEW_CONTRACT
            )
            self.assertIs(payload["named_lane_eligible"], False)
            self.assertEqual(payload["review_status"], "not-run")
            self.assertFalse(payload["created_attempt"])
            self.assertEqual(payload["review_range"], f"{base_sha}..{head_sha}")
            self.assertEqual(tuple(checkouts.iterdir()), ())
            self.assertEqual(
                tuple(path.name for path in retention.iterdir()),
                ("retention.lock",),
            )

    def _assert_raw_detached_checkout_and_sealed_diff(
        self,
        root: pathlib.Path,
        *,
        object_format: str,
    ) -> None:
        repo, base_sha, head_sha = _build_repository(
            root,
            object_format=object_format,
        )
        info = inspect_repository(
            repo=repo,
            base_sha=base_sha,
            head_sha=head_sha,
            git_executable=str(GIT),
        )
        self.assertEqual(info.object_format, object_format)
        expected_hex_length = 64 if object_format == "sha256" else 40
        self.assertEqual(len(base_sha), expected_hex_length)
        self.assertEqual(len(head_sha), expected_hex_length)
        base = enumerate_tree(info, base_sha)
        head = enumerate_tree(info, head_sha)
        self.assertEqual(
            tuple(entry.path for entry in head.entries),
            (
                b".gitattributes",
                b"base.txt",
                b"data-link",
                b"nested/data.txt",
                b"tool.sh",
            ),
        )
        self.assertTrue(any(entry.is_symlink for entry in head.entries))

        checkout = root / "checkout"
        registration = add_detached_worktree(info, checkout)
        source = root / "source.diff"
        source_content = b"diff --git a/base.txt b/base.txt\n+head\n"
        source.write_bytes(source_content)
        source.chmod(0o600)
        source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        namespace = root / "name-probe"
        namespace.mkdir(mode=0o700)
        materializer: RawMaterializer | None = None
        try:
            initialize_index(info, registration)
            semantics = probe_name_semantics(namespace)
            base_entries, head_entries = validate_namespaces(
                base,
                head,
                semantics=semantics,
                checkout_root=checkout,
            )
            graph = read_and_validate_symlink_graphs(
                info,
                base,
                head,
                base_entries=base_entries,
                head_entries=head_entries,
                semantics=semantics,
            )
            source_identity = identity_from_stat(os.fstat(source_fd))
            custody = HelperCustody(
                state_dir=str(root),
                state_identity=identity_from_stat(os.stat(root)),
                workspace_root=str(root),
                source_path=str(source),
                source_identity=source_identity,
                cleanup_lock_path=str(root / "unused.lock"),
                cleanup_lock_identity=source_identity,
                review_range=f"{base_sha}..{head_sha}",
                base_sha=base_sha,
                head_sha=head_sha,
                diff_length=len(source_content),
                diff_sha256=sha256_bytes(source_content),
                preflight_sha256="0" * 64,
                control_state_sha256="1" * 64,
            )
            materializer = RawMaterializer(
                info=info,
                registration=registration,
                base=base,
                head=head,
                semantics=semantics,
                graph=graph,
                source_fd=source_fd,
                custody=custody,
                deadline=time.monotonic() + 60,
                checkout_root_bound=1024 * 1024 * 1024,
                git_admin_bound=1024 * 1024 * 1024,
                view_path=root / "sanitized-git-view",
            )
            materializer.phase1()
            with mock.patch(
                "review_supervisor.checkout.rename_exchange",
                wraps=rename_exchange,
            ) as exchange:
                evidence = materializer.materialize()
            exchange.assert_called_once()
            self.assertEqual(
                evidence.sealed_diff_sha256,
                sha256_bytes(source_content),
            )
            self.assertEqual(
                (checkout / ".codex-review" / "review.diff").read_bytes(),
                source_content,
            )
            self.assertFalse((root / "sanitized-git-view").exists())
            self.assertEqual(os.readlink(checkout / "data-link"), "nested/data.txt")
        finally:
            if materializer is not None:
                materializer.close()
            os.close(source_fd)
            if checkout.exists() and registration.registration.exists():
                remove_both_present_worktree(info, registration)
            if namespace.exists():
                namespace.rmdir()
        verify_worktree_absent(info, checkout)

    def test_raw_detached_checkout_and_sealed_diff(self) -> None:
        with owned_temporary_directory("git-checkout-") as root:
            self._assert_raw_detached_checkout_and_sealed_diff(
                root,
                object_format="sha1",
            )

    def test_sha256_raw_view_check_attr_index_and_materialization(self) -> None:
        with owned_temporary_directory("git-sha256-checkout-") as root:
            support_probe = _init_repository(
                root / "sha256-support-probe",
                object_format="sha256",
            )
            if support_probe.returncode != 0:
                self.skipTest(
                    "git init --object-format=sha256 is unsupported: "
                    + support_probe.stderr.decode("utf-8", "replace").strip()
                )
            self.assertEqual(
                _git(
                    root / "sha256-support-probe", "rev-parse", "--show-object-format"
                ),
                b"sha256",
            )
            self._assert_raw_detached_checkout_and_sealed_diff(
                root,
                object_format="sha256",
            )

    def test_git_environment_disables_network_and_filters(self) -> None:
        environment = sanitized_git_environment()
        self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(environment["GIT_LFS_SKIP_SMUDGE"], "1")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["GIT_PROTOCOL_FROM_USER"], "0")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], "/dev/null")

    def test_materializer_blocks_small_lfs_pointer_content(self) -> None:
        with owned_temporary_directory("git-lfs-block-") as root:
            repo, base_sha, _ = _build_repository(root)
            pointer = (
                b"version https://git-lfs.github.com/spec/v1\n"
                b"oid sha256:" + b"a" * 64 + b"\n"
                b"size +0001\n"
            )
            (repo / "pointer.bin").write_bytes(pointer)
            _git(repo, "add", "--", "pointer.bin")
            _git(repo, "commit", "-q", "-m", "pointer")
            head_sha = _git(repo, "rev-parse", "HEAD").decode("ascii")
            info = inspect_repository(
                repo=repo,
                base_sha=base_sha,
                head_sha=head_sha,
                git_executable=str(GIT),
            )
            base = enumerate_tree(info, base_sha)
            head = enumerate_tree(info, head_sha)
            checkout = root / "checkout"
            registration = add_detached_worktree(info, checkout)
            namespace = root / "name-probe"
            namespace.mkdir(mode=0o700)
            source = root / "source.diff"
            source.write_bytes(b"diff\n")
            source.chmod(0o600)
            source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            materializer: RawMaterializer | None = None
            try:
                initialize_index(info, registration)
                semantics = probe_name_semantics(namespace)
                base_entries, head_entries = validate_namespaces(
                    base,
                    head,
                    semantics=semantics,
                    checkout_root=checkout,
                )
                graph = read_and_validate_symlink_graphs(
                    info,
                    base,
                    head,
                    base_entries=base_entries,
                    head_entries=head_entries,
                    semantics=semantics,
                )
                source_identity = identity_from_stat(os.fstat(source_fd))
                custody = HelperCustody(
                    state_dir=str(root),
                    state_identity=identity_from_stat(os.stat(root)),
                    workspace_root=str(root),
                    source_path=str(source),
                    source_identity=source_identity,
                    cleanup_lock_path=str(root / "unused.lock"),
                    cleanup_lock_identity=source_identity,
                    review_range=f"{base_sha}..{head_sha}",
                    base_sha=base_sha,
                    head_sha=head_sha,
                    diff_length=5,
                    diff_sha256=sha256_bytes(b"diff\n"),
                    preflight_sha256="0" * 64,
                    control_state_sha256="1" * 64,
                )
                materializer = RawMaterializer(
                    info=info,
                    registration=registration,
                    base=base,
                    head=head,
                    semantics=semantics,
                    graph=graph,
                    source_fd=source_fd,
                    custody=custody,
                    deadline=time.monotonic() + 60,
                    checkout_root_bound=1024 * 1024 * 1024,
                    git_admin_bound=1024 * 1024 * 1024,
                    view_path=root / "sanitized-git-view",
                )
                materializer.phase1()
                with self.assertRaises(SupervisorError) as raised:
                    materializer.materialize()
                self.assertEqual(
                    raised.exception.failure.code,
                    "blocked-checkout-lfs-pointer",
                )
            finally:
                if materializer is not None:
                    materializer.close()
                os.close(source_fd)
                if checkout.exists() and registration.registration.exists():
                    remove_both_present_worktree(info, registration)
                if namespace.exists():
                    namespace.rmdir()


if __name__ == "__main__":
    unittest.main()
