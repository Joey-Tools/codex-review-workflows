from __future__ import annotations

import ast
import contextlib
import functools
import hashlib
import io
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import py_compile
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import unittest
import venv
from collections.abc import Callable
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import named_lane as named_lane_runtime  # noqa: E402
from review_runtime import review_workspace as review_workspace_runtime  # noqa: E402
from review_runtime.common import (  # noqa: E402
    BoundedCapture,
    ForwardedSignal,
    ReviewOutputDrainError,
    ReviewOutputLimitError,
    ReviewProcessLeakError,
    ReviewTimeoutError,
    TRUSTED_PATH,
)
from review_runtime.named_lane import (  # noqa: E402
    LEGACY_PREFIX_RECEIPT_SCHEMA_VERSION,
    MATERIALIZER_BASE_REF,
    MATERIALIZER_HEAD_REF,
    SANITIZED_GIT_ARGV_PREFIX_CONFORMANCE,
    SANITIZED_GIT_ARGV_PREFIX_ENCODING,
    SANITIZED_GIT_ARGV_PREFIX_PROFILE,
    SANITIZED_GIT_ARGV_PREFIX_RECEIPT_IDENTITY_ALGORITHM,
    SANITIZED_GIT_ARGV_PREFIX_RECEIPT_SCHEMA_VERSION,
    SYMLINK_COUNT_LIMIT,
    LegacyPrefixReceiptInconclusive,
    NamedLaneGuardError,
    _read_symlink_blobs,
    _validate_materializer_git_version,
    _validate_materialized_gitlink,
    _validate_materialized_symlink,
    build_sanitized_git_argv_prefix,
    main as _named_lane_main,
    materialize_worktree,
    run_claude as _run_claude,
    sanitized_git_argv_prefix_receipt,
    validate_sanitized_git_argv_prefix,
    validate_sanitized_git_argv_prefix_receipt,
    validate_published_sanitized_git_argv_prefix_receipt,
    validate_worktree,
)


def git(repo: pathlib.Path, *arguments: str) -> str:
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
        }
    )
    completed = subprocess.run(
        ("git", "-C", str(repo), *arguments),
        check=True,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def visible_exception_text(error: BaseException) -> str:
    """Render notes or the Python 3.10 fallback cause chain alike."""

    return "".join(traceback.format_exception(type(error), error, error.__traceback__))


def call_run_claude(**kwargs: object) -> dict[str, object]:
    """Call the production API only with an explicit parent binding."""

    if "source_worktree" not in kwargs:
        worktree = pathlib.Path(kwargs["worktree"])
        kwargs["source_worktree"] = worktree.parent / "source-control"
    if "preflight_result" not in kwargs:
        command = kwargs["command"]
        executable = pathlib.Path(command[0])
        kwargs["preflight_result"] = executable.with_name(
            f"{executable.name}.preflight.json"
        )
    binding_fields = {
        "source_authority_binding",
        "source_authority_binding_sha256",
    }
    if not binding_fields.issubset(kwargs):
        raise AssertionError(
            "run_claude tests must supply both values from a prepared source receipt"
        )
    return _run_claude(**kwargs)


def call_named_lane_main(argv: object) -> int:
    """Call the production CLI entrypoint without synthesizing guard input."""

    return _named_lane_main(tuple(argv))


def retired_public_commands(*commands: str) -> object:
    """Convert a legacy CLI test into an assertion that its route is absent."""

    def decorate(legacy_test: object) -> object:
        @functools.wraps(legacy_test)
        def assert_retired(self: unittest.TestCase) -> None:
            for command in commands:
                with (
                    self.subTest(command=command),
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit) as caught,
                ):
                    self.named_lane_main((command,))
                self.assertEqual(caught.exception.code, 2)

        return assert_retired

    return decorate


class NamedLaneGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        temp_root = pathlib.Path(tempfile.gettempdir()).resolve()
        self.temporary = tempfile.TemporaryDirectory(
            prefix="named-lane-test-",
            dir=temp_root,
        )
        self.root = pathlib.Path(self.temporary.name)
        self._prefix_test_workspaces: list[
            review_workspace_runtime.PreparedWorkspace
        ] = []
        self._prepared_source_authority_receipts: dict[
            pathlib.Path, dict[str, object]
        ] = {}
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.source_control = self.root / "source-control"
        self.source_control.mkdir(mode=0o700)
        git(self.source_control, "init", "-b", "master")
        git(self.repo, "init", "-b", "master")
        git(self.repo, "config", "user.name", "Named Lane Test")
        git(self.repo, "config", "user.email", "named-lane@example.invalid")
        git(self.repo, "config", "commit.gpgsign", "false")
        method_names = set(getattr(type(self), self._testMethodName).__code__.co_names)
        if method_names.intersection(
            {"run_claude", "named_lane_main", "isolated_guard_command"}
        ):
            # Prepare before the test installs time, signal, filesystem, or
            # process mocks. The cached receipt is the explicit parent input.
            self.prepared_source_authority_receipt(self.source_control)

    def tearDown(self) -> None:
        for prepared in reversed(self._prefix_test_workspaces):
            if prepared.root.exists():
                review_workspace_runtime.cleanup_workspace(
                    prepared.root,
                    prepared.cleanup_token,
                )
        self.temporary.cleanup()

    def commit(self, message: str = "fixture") -> str:
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-m", message)
        return git(self.repo, "rev-parse", "HEAD")

    def workspace_range(self) -> tuple[str, str]:
        (self.repo / "AGENTS.md").write_text("base guidance\n", encoding="utf-8")
        base = self.commit("workspace base")
        (self.repo / "tracked.txt").write_text("workspace head\n", encoding="utf-8")
        head = self.commit("workspace head")
        return base, head

    def prepared_review_workspace(
        self,
        name: str,
    ) -> tuple[review_workspace_runtime.PreparedWorkspace, str, str]:
        base, head = self.workspace_range()
        prepared = review_workspace_runtime.prepare_workspace(
            self.repo.resolve(),
            self.root / name,
            base,
            head,
        )
        self._prefix_test_workspaces.append(prepared)
        return prepared, base, head

    def source_control_range(self) -> tuple[str, str]:
        git(self.source_control, "config", "user.name", "Named Lane Source Test")
        git(
            self.source_control,
            "config",
            "user.email",
            "named-lane-source@example.invalid",
        )
        git(self.source_control, "config", "commit.gpgsign", "false")
        tracked = self.source_control / "tracked.txt"
        tracked.write_text("source base\n", encoding="utf-8")
        git(self.source_control, "add", "tracked.txt")
        git(self.source_control, "commit", "-m", "source base")
        base = git(self.source_control, "rev-parse", "HEAD")
        tracked.write_text("source head\n", encoding="utf-8")
        git(self.source_control, "commit", "-am", "source head")
        return base, git(self.source_control, "rev-parse", "HEAD")

    def prepare_source_authority_receipt(
        self,
        source: pathlib.Path,
        *,
        base: str,
        head: str,
        name: str,
    ) -> dict[str, object]:
        prepared = review_workspace_runtime.prepare_workspace(
            source,
            self.root / f"{name}-prepared-workspace",
            base,
            head,
        )
        self._prefix_test_workspaces.append(prepared)
        return prepared.receipt()

    def prepared_source_authority_receipt(
        self,
        source: pathlib.Path,
    ) -> dict[str, object]:
        """Prepare and cache exact parent input for unrelated Claude unit tests."""

        source = source.resolve()
        cached = self._prepared_source_authority_receipts.get(source)
        if cached is not None:
            return cached
        try:
            head = git(source, "rev-parse", "HEAD")
        except subprocess.CalledProcessError:
            git(source, "config", "user.name", "Named Lane Source Test")
            git(
                source,
                "config",
                "user.email",
                "named-lane-source@example.invalid",
            )
            git(source, "config", "commit.gpgsign", "false")
            git(source, "commit", "--allow-empty", "-m", "source authority fixture")
            head = git(source, "rev-parse", "HEAD")
        receipt = self.prepare_source_authority_receipt(
            source,
            base=head,
            head=head,
            name=f"source-authority-{len(self._prepared_source_authority_receipts)}",
        )
        self._prepared_source_authority_receipts[source] = receipt
        return receipt

    def run_claude(self, **kwargs: object) -> dict[str, object]:
        """Call Claude with exact cached prepare-receipt authority by default."""

        binding_fields = {
            "source_authority_binding",
            "source_authority_binding_sha256",
        }
        supplied = binding_fields.intersection(kwargs)
        if supplied and supplied != binding_fields:
            raise AssertionError(
                "Claude parent binding fields must be supplied together"
            )
        if not supplied:
            source = pathlib.Path(
                kwargs.get(
                    "source_worktree",
                    pathlib.Path(kwargs["worktree"]).parent / "source-control",
                )
            )
            receipt = self.prepared_source_authority_receipt(source)
            kwargs["source_authority_binding"] = receipt["source_authority_binding"]
            kwargs["source_authority_binding_sha256"] = receipt[
                "source_authority_binding_sha256"
            ]
        return call_run_claude(**kwargs)

    def named_lane_main(self, argv: object) -> int:
        """Call the CLI with exact cached prepare-receipt authority input."""

        arguments = list(argv)
        if (
            arguments
            and arguments[0] == "run-claude"
            and "--source-authority-binding-json" not in arguments
        ):
            if "--source-worktree" not in arguments:
                raise AssertionError("run-claude test argv lacks --source-worktree")
            source = pathlib.Path(arguments[arguments.index("--source-worktree") + 1])
            receipt = self.prepared_source_authority_receipt(source)
            canonical = (
                review_workspace_runtime.canonical_source_authority_binding_bytes(
                    receipt["source_authority_binding"]
                )
            )
            self.assertEqual(
                hashlib.sha256(canonical).hexdigest(),
                receipt["source_authority_binding_sha256"],
            )
            arguments[1:1] = (
                "--source-authority-binding-json",
                canonical.decode("utf-8"),
                "--source-authority-binding-sha256",
                receipt["source_authority_binding_sha256"],
            )
        return call_named_lane_main(tuple(arguments))

    def run_codex_git_prefix_committed_cleanup_fault(
        self,
        *,
        mode: str,
        prepared: review_workspace_runtime.PreparedWorkspace,
        base: str,
        head: str,
    ) -> subprocess.CompletedProcess[str]:
        probe = """
import signal
import sys

sys.path.insert(0, sys.argv[1])
from review_runtime import named_lane
from review_runtime.common import ForwardedSignal

real_restore = named_lane.restore_signal_mask
restore_calls = 0

def fail_committed_cleanup_restore(previous):
    global restore_calls
    restore_calls += 1
    real_restore(previous)
    if restore_calls == 2:
        raise OSError("synthetic committed context cleanup restore failure")

named_lane.restore_signal_mask = fail_committed_cleanup_restore
if sys.argv[2] == "failure":
    def fail_prefix_receipt(**_kwargs):
        raise ForwardedSignal(signal.SIGTERM)

    named_lane.sanitized_git_argv_prefix_receipt = fail_prefix_receipt

returncode = named_lane.main(
    (
        "codex-git-prefix",
        "--worktree",
        sys.argv[3],
        "--base",
        sys.argv[4],
        "--head",
        sys.argv[5],
        "--git-executable",
        sys.argv[6],
    )
)
raise SystemExit(returncode)
"""
        return subprocess.run(
            (
                sys.executable,
                "-I",
                "-B",
                "-S",
                "-c",
                probe,
                str(SCRIPTS),
                mode,
                str(prepared.root),
                base,
                head,
                str(named_lane_runtime.resolve_git()),
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def publish_prefix_receipt(
        self,
        *,
        prepared: review_workspace_runtime.PreparedWorkspace,
        base: str,
        head: str,
        name: str,
    ) -> tuple[pathlib.Path, dict[str, object]]:
        issued = subprocess.run(
            (
                sys.executable,
                "-I",
                "-B",
                "-S",
                str(SCRIPTS / "named_lane_guard"),
                "codex-git-prefix",
                "--worktree",
                str(prepared.root),
                "--base",
                base,
                "--head",
                head,
                "--git-executable",
                str(named_lane_runtime.resolve_git()),
            ),
            cwd=self.root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
        self.assertEqual(issued.returncode, 0, issued.stderr.decode("utf-8", "replace"))
        self.assertEqual(issued.stderr, b"")
        receipt = json.loads(issued.stdout)
        receipt_directory = self.root / f"{name}-control"
        receipt_directory.mkdir(mode=0o700)
        receipt_path = receipt_directory / "codex-git-prefix-receipt.json"
        receipt_path.write_bytes(issued.stdout)
        receipt_path.chmod(0o600)
        return receipt_path, receipt

    def run_published_prefix_receipt_validation(
        self,
        *,
        receipt_path: pathlib.Path,
        prepared: review_workspace_runtime.PreparedWorkspace,
        base: str,
        head: str,
        expected_receipt_sha256: str,
    ) -> subprocess.CompletedProcess[str]:
        arguments = self.published_prefix_receipt_validation_argv(
            receipt_path=receipt_path,
            prepared=prepared,
            base=base,
            head=head,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        return subprocess.run(
            (
                sys.executable,
                "-I",
                "-B",
                "-S",
                str(SCRIPTS / "named_lane_guard"),
                *arguments,
            ),
            cwd=self.root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )

    def published_prefix_receipt_validation_argv(
        self,
        *,
        receipt_path: pathlib.Path,
        prepared: review_workspace_runtime.PreparedWorkspace,
        base: str,
        head: str,
        expected_receipt_sha256: str,
    ) -> tuple[str, ...]:
        return (
            "validate-codex-git-prefix-receipt",
            "--receipt-file",
            str(receipt_path),
            "--expected-receipt-sha256",
            expected_receipt_sha256,
            "--worktree",
            str(prepared.root),
            "--base",
            base,
            "--head",
            head,
            "--git-executable",
            str(named_lane_runtime.resolve_git()),
        )

    def descriptor_close_fault_injector(
        self,
        faults: tuple[BaseException | None, ...],
        attempts: list[int],
    ) -> Callable[
        [tuple[tuple[str, int], ...]],
        list[tuple[str, BaseException]],
    ]:
        real_attempt = review_workspace_runtime._attempt_workspace_descriptor_closes
        real_close = os.close

        def inject(
            descriptors: tuple[tuple[str, int], ...],
        ) -> list[tuple[str, BaseException]]:
            fault_index = 0

            def close_then_fault(descriptor: int) -> None:
                nonlocal fault_index
                attempts.append(descriptor)
                real_close(descriptor)
                if fault_index >= len(faults):
                    raise AssertionError("unexpected descriptor close attempt")
                fault = faults[fault_index]
                fault_index += 1
                if fault is not None:
                    raise fault

            with mock.patch.object(
                review_workspace_runtime.os,
                "close",
                side_effect=close_then_fault,
            ):
                failures = real_attempt(descriptors)
            self.assertEqual(fault_index, len(faults))
            return failures

        return inject

    def test_codex_git_prefix_v2_matches_exact_accepted_adapter_sequence(
        self,
    ) -> None:
        worktree = self.root / "review-workspace"
        git_executable = pathlib.Path("/usr/bin/git")
        expected = (
            "/usr/bin/env",
            "-i",
            f"PATH={TRUSTED_PATH}",
            "LANG=C",
            "LC_ALL=C",
            "GIT_ASKPASS=/usr/bin/false",
            "GIT_ATTR_NOSYSTEM=1",
            f"GIT_CEILING_DIRECTORIES={self.root}",
            "GIT_CONFIG_GLOBAL=/dev/null",
            "GIT_CONFIG_SYSTEM=/dev/null",
            "GIT_CONFIG_NOSYSTEM=1",
            "GIT_GRAFT_FILE=/dev/null",
            "GIT_LITERAL_PATHSPECS=1",
            "GIT_NO_LAZY_FETCH=1",
            "GIT_TERMINAL_PROMPT=0",
            "GIT_NO_REPLACE_OBJECTS=1",
            "GIT_OPTIONAL_LOCKS=0",
            "PAGER=cat",
            "GIT_PAGER=cat",
            "/usr/bin/git",
            "--no-pager",
            "-c",
            "core.commitGraph=false",
            "-c",
            "core.checkStat=default",
            "-c",
            "core.multiPackIndex=false",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.fileMode=true",
            "-c",
            "core.ignoreStat=false",
            "-c",
            "core.trustCtime=true",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "diff.external=",
            "-c",
            "color.ui=false",
            "-C",
            str(worktree),
        )

        actual = build_sanitized_git_argv_prefix(
            worktree=worktree,
            git_executable=git_executable,
        )
        self.assertEqual(actual, expected)
        self.assertNotIn("--no-lazy-fetch", actual)
        self.assertEqual(actual[actual.index("--no-pager") + 1], "-c")
        self.assertEqual(actual.count("GIT_NO_LAZY_FETCH=1"), 1)
        self.assertEqual(actual.count("GIT_LITERAL_PATHSPECS=1"), 1)
        self.assertEqual(
            validate_sanitized_git_argv_prefix(
                actual,
                worktree=worktree,
                git_executable=git_executable,
            ),
            expected,
        )

    def test_codex_git_prefix_rejects_recomputed_digest_for_nonprofile_tokens(
        self,
    ) -> None:
        worktree = self.root / "review-workspace"
        git_executable = pathlib.Path("/usr/bin/git")
        generated = list(
            build_sanitized_git_argv_prefix(
                worktree=worktree,
                git_executable=git_executable,
            )
        )
        generated.insert(generated.index("--no-pager") + 1, "--no-lazy-fetch")
        recomputed_digest = hashlib.sha256(
            json.dumps(
                generated,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        self.assertRegex(recomputed_digest, r"\A[0-9a-f]{64}\Z")

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "does not conform to sanitized-git-argv-prefix-v2",
        ):
            validate_sanitized_git_argv_prefix(
                generated,
                worktree=worktree,
                git_executable=git_executable,
            )

    def test_codex_git_prefix_command_emits_closed_machine_receipt(self) -> None:
        prepared, base, head = self.prepared_review_workspace("review-workspace")
        worktree = prepared.root
        git_executable = named_lane_runtime.resolve_git()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = self.named_lane_main(
                (
                    "codex-git-prefix",
                    "--worktree",
                    str(worktree),
                    "--base",
                    base,
                    "--head",
                    head,
                    "--git-executable",
                    str(git_executable),
                )
            )
        self.assertEqual(result, 0)
        receipt = json.loads(output.getvalue())
        self.assertEqual(
            receipt,
            validate_sanitized_git_argv_prefix_receipt(
                receipt,
                worktree=worktree,
                base=base,
                head=head,
                git_executable=git_executable,
            ),
        )
        self.assertEqual(
            receipt["schema_version"],
            SANITIZED_GIT_ARGV_PREFIX_RECEIPT_SCHEMA_VERSION,
        )
        self.assertEqual(receipt["prefix_profile"], SANITIZED_GIT_ARGV_PREFIX_PROFILE)
        self.assertEqual(
            receipt["sanitized_git_argv_prefix_conformance"],
            SANITIZED_GIT_ARGV_PREFIX_CONFORMANCE,
        )
        self.assertEqual(
            receipt["sanitized_git_argv_prefix_encoding"],
            SANITIZED_GIT_ARGV_PREFIX_ENCODING,
        )
        self.assertEqual(receipt["no_lazy_fetch_control"], "GIT_NO_LAZY_FETCH=1")
        self.assertNotIn("--no-lazy-fetch", receipt["sanitized_git_argv_prefix"])
        self.assertEqual(receipt["base"], base)
        self.assertEqual(receipt["head"], head)
        self.assertEqual(receipt["worktree"], str(worktree))
        self.assertEqual(receipt["git_executable"], str(git_executable))
        self.assertEqual(
            receipt["workspace_validation_receipt"]["command"],
            "validate-workspace",
        )
        self.assertEqual(
            receipt["workspace_validation_receipt"]["base"],
            receipt["base"],
        )
        self.assertEqual(
            receipt["workspace_validation_receipt"]["head"],
            receipt["head"],
        )
        self.assertEqual(
            receipt["workspace_validation_receipt"]["worktree"],
            receipt["worktree"],
        )
        self.assertEqual(
            receipt["receipt_identity_algorithm"],
            SANITIZED_GIT_ARGV_PREFIX_RECEIPT_IDENTITY_ALGORITHM,
        )
        receipt_without_digest = dict(receipt)
        receipt_without_digest.pop("receipt_sha256")
        self.assertEqual(
            receipt["receipt_sha256"],
            hashlib.sha256(
                json.dumps(
                    receipt_without_digest,
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest(),
        )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "Codex Git prefix signal custody requires POSIX pthread masks",
    )
    def test_codex_git_prefix_committed_success_cleanup_fault_keeps_success(
        self,
    ) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "prefix-committed-success-cleanup-fault"
        )

        completed = self.run_codex_git_prefix_committed_cleanup_fault(
            mode="success",
            prepared=prepared,
            base=base,
            head=head,
        )

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        self.assertEqual(json.loads(completed.stdout)["command"], "codex-git-prefix")

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "Codex Git prefix signal custody requires POSIX pthread masks",
    )
    def test_codex_git_prefix_committed_failure_cleanup_fault_keeps_failure(
        self,
    ) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "prefix-committed-failure-cleanup-fault"
        )

        completed = self.run_codex_git_prefix_committed_cleanup_fault(
            mode="failure",
            prepared=prepared,
            base=base,
            head=head,
        )

        self.assertEqual(completed.returncode, 128 + signal.SIGTERM)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(len(completed.stderr.splitlines()), 1)
        self.assertEqual(
            json.loads(completed.stderr),
            {"status": "blocked-safety", "reason": "forwarded-signal"},
        )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "Codex Git prefix signal custody requires POSIX pthread masks",
    )
    def test_codex_git_prefix_signal_during_validation_uses_structured_handoff(
        self,
    ) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "prefix-validation-signal-workspace"
        )
        git_executable = named_lane_runtime.resolve_git()
        original_validate = named_lane_runtime.validate_workspace
        structured_handler_observed = False
        signal_queued = False

        def raise_forwarded_signal(signum: int, _frame: object) -> None:
            raise ForwardedSignal(signal.Signals(signum))

        def validate_then_signal(*args: object, **kwargs: object) -> object:
            nonlocal structured_handler_observed, signal_queued
            result = original_validate(*args, **kwargs)
            structured_handler_observed = (
                signal.getsignal(signal.SIGTERM) is not raise_forwarded_signal
            )
            signal_queued = True
            signal.raise_signal(signal.SIGTERM)
            return result

        previous_handler = signal.getsignal(signal.SIGTERM)
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM})
        signal.signal(signal.SIGTERM, raise_forwarded_signal)
        stdout = io.StringIO()
        stderr = io.StringIO()
        try:
            with (
                mock.patch.object(
                    named_lane_runtime,
                    "validate_workspace",
                    side_effect=validate_then_signal,
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                returncode = self.named_lane_main(
                    (
                        "codex-git-prefix",
                        "--worktree",
                        str(prepared.root),
                        "--base",
                        base,
                        "--head",
                        head,
                        "--git-executable",
                        str(git_executable),
                    )
                )
            self.assertEqual(returncode, 128 + signal.SIGTERM)
            self.assertTrue(signal_queued)
            self.assertTrue(structured_handler_observed)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(
                json.loads(stderr.getvalue()),
                {"status": "blocked-safety", "reason": "forwarded-signal"},
            )
            self.assertIs(signal.getsignal(signal.SIGTERM), raise_forwarded_signal)
            self.assertEqual(
                signal.pthread_sigmask(signal.SIG_BLOCK, set()),
                set(previous_mask) - {signal.SIGTERM},
            )
        finally:
            signal.signal(signal.SIGTERM, previous_handler)
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    def test_codex_git_prefix_guard_entrypoint_issues_composite_receipt(self) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "guard-entrypoint-review-workspace"
        )
        git_executable = named_lane_runtime.resolve_git()
        completed = subprocess.run(
            (
                sys.executable,
                "-I",
                "-B",
                "-S",
                str(SCRIPTS / "named_lane_guard"),
                "codex-git-prefix",
                "--worktree",
                str(prepared.root),
                "--base",
                base,
                "--head",
                head,
                "--git-executable",
                str(git_executable),
            ),
            cwd=self.root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        receipt = json.loads(completed.stdout)
        self.assertEqual(receipt["base"], base)
        self.assertEqual(receipt["head"], head)
        self.assertEqual(receipt["worktree"], str(prepared.root))
        self.assertEqual(
            receipt["schema_version"],
            SANITIZED_GIT_ARGV_PREFIX_RECEIPT_SCHEMA_VERSION,
        )
        validate_sanitized_git_argv_prefix_receipt(
            receipt,
            worktree=prepared.root,
            base=base,
            head=head,
            git_executable=git_executable,
        )

    def test_guard_live_consumer_accepts_same_published_prefix_receipt(self) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "live-consumer-review-workspace"
        )
        receipt_path, receipt = self.publish_prefix_receipt(
            prepared=prepared,
            base=base,
            head=head,
            name="valid-prefix-receipt",
        )

        completed = self.run_published_prefix_receipt_validation(
            receipt_path=receipt_path,
            prepared=prepared,
            base=base,
            head=head,
            expected_receipt_sha256=str(receipt["receipt_sha256"]),
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(json.loads(completed.stdout), receipt)
        self.assertEqual(completed.stdout.encode("utf-8"), receipt_path.read_bytes())

    def test_guard_live_consumer_rejects_stale_published_prefix_receipt(self) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "stale-live-consumer-review-workspace"
        )
        receipt_path, receipt = self.publish_prefix_receipt(
            prepared=prepared,
            base=base,
            head=head,
            name="stale-prefix-receipt",
        )
        (prepared.root / "tracked.txt").write_text(
            "changed after prefix publication\n",
            encoding="utf-8",
        )

        completed = self.run_published_prefix_receipt_validation(
            receipt_path=receipt_path,
            prepared=prepared,
            base=base,
            head=head,
            expected_receipt_sha256=str(receipt["receipt_sha256"]),
        )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        failure = json.loads(completed.stderr)
        self.assertEqual(failure["status"], "blocked-safety")
        self.assertTrue(failure["reason"])

    def test_guard_live_consumer_rejects_tampered_published_prefix_receipt(
        self,
    ) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "tampered-live-consumer-review-workspace"
        )
        receipt_path, receipt = self.publish_prefix_receipt(
            prepared=prepared,
            base=base,
            head=head,
            name="tampered-prefix-receipt",
        )
        expected_receipt_sha256 = str(receipt["receipt_sha256"])
        receipt["git_version"] = "git version 99.0.0"
        receipt_path.write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        receipt_path.chmod(0o600)

        completed = self.run_published_prefix_receipt_validation(
            receipt_path=receipt_path,
            prepared=prepared,
            base=base,
            head=head,
            expected_receipt_sha256=expected_receipt_sha256,
        )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(
            json.loads(completed.stderr),
            {
                "status": "blocked-safety",
                "reason": "sanitized Git argv prefix Git version binding is invalid",
            },
        )

    def test_guard_live_consumer_does_not_reinvoke_prefix_issuer(self) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "issuer-independence-review-workspace"
        )
        receipt_path, receipt = self.publish_prefix_receipt(
            prepared=prepared,
            base=base,
            head=head,
            name="issuer-independence-prefix-receipt",
        )
        arguments = self.published_prefix_receipt_validation_argv(
            receipt_path=receipt_path,
            prepared=prepared,
            base=base,
            head=head,
            expected_receipt_sha256=str(receipt["receipt_sha256"]),
        )
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            mock.patch.object(
                named_lane_runtime,
                "sanitized_git_argv_prefix_receipt",
                side_effect=AssertionError("consumer must not invoke issuer"),
            ) as issuer,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(arguments)

        self.assertEqual(returncode, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(json.loads(stdout.getvalue()), receipt)
        issuer.assert_not_called()

    def test_guard_live_consumer_rejects_wrong_scope_and_expected_identity(
        self,
    ) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "wrong-scope-live-consumer-review-workspace"
        )
        receipt_path, receipt = self.publish_prefix_receipt(
            prepared=prepared,
            base=base,
            head=head,
            name="wrong-scope-prefix-receipt",
        )
        expected = str(receipt["receipt_sha256"])

        wrong_identity = self.run_published_prefix_receipt_validation(
            receipt_path=receipt_path,
            prepared=prepared,
            base=base,
            head=head,
            expected_receipt_sha256="0" * 64,
        )
        wrong_scope = self.run_published_prefix_receipt_validation(
            receipt_path=receipt_path,
            prepared=prepared,
            base=base,
            head=base,
            expected_receipt_sha256=expected,
        )

        for completed in (wrong_identity, wrong_scope):
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(json.loads(completed.stderr)["status"], "blocked-safety")
        self.assertIn("retained expected identity", wrong_identity.stderr)
        self.assertIn("receipt head is invalid", wrong_scope.stderr)

    def test_guard_live_consumer_rejects_hardlink_and_inside_worktree(
        self,
    ) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "path-policy-live-consumer-review-workspace"
        )
        receipt_path, receipt = self.publish_prefix_receipt(
            prepared=prepared,
            base=base,
            head=head,
            name="path-policy-prefix-receipt",
        )
        expected = str(receipt["receipt_sha256"])
        hardlink = receipt_path.with_name("receipt-hardlink.json")
        os.link(receipt_path, hardlink)

        linked = self.run_published_prefix_receipt_validation(
            receipt_path=receipt_path,
            prepared=prepared,
            base=base,
            head=head,
            expected_receipt_sha256=expected,
        )
        inside = self.run_published_prefix_receipt_validation(
            receipt_path=prepared.root / "tracked.txt",
            prepared=prepared,
            base=base,
            head=head,
            expected_receipt_sha256=expected,
        )

        self.assertEqual(linked.returncode, 2)
        self.assertIn("single-link regular file", linked.stderr)
        self.assertEqual(inside.returncode, 2)
        self.assertIn("must stay outside the worktree", inside.stderr)

    def test_guard_live_consumer_rejects_unsafe_receipt_path_types_and_modes(
        self,
    ) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "unsafe-path-live-consumer-review-workspace"
        )
        receipt_path, receipt = self.publish_prefix_receipt(
            prepared=prepared,
            base=base,
            head=head,
            name="unsafe-path-prefix-receipt",
        )
        expected = str(receipt["receipt_sha256"])
        symlink_path = receipt_path.with_name("symlink.json")
        symlink_path.symlink_to(receipt_path.name)
        fifo_path = receipt_path.with_name("receipt.fifo")
        os.mkfifo(fifo_path, mode=0o600)
        unsafe_mode_path = receipt_path.with_name("unsafe-mode.json")
        unsafe_mode_path.write_bytes(receipt_path.read_bytes())
        unsafe_mode_path.chmod(0o666)
        unsafe_parent = self.root / "unsafe-receipt-parent"
        unsafe_parent.mkdir(mode=0o755)
        unsafe_parent_path = unsafe_parent / "receipt.json"
        unsafe_parent_path.write_bytes(receipt_path.read_bytes())
        unsafe_parent_path.chmod(0o600)

        for label, candidate in (
            ("symlink", symlink_path),
            ("fifo", fifo_path),
            ("group-world-writable", unsafe_mode_path),
            ("non-private-parent", unsafe_parent_path),
        ):
            with self.subTest(label=label):
                completed = self.run_published_prefix_receipt_validation(
                    receipt_path=candidate,
                    prepared=prepared,
                    base=base,
                    head=head,
                    expected_receipt_sha256=expected,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stdout, "")
                self.assertEqual(
                    json.loads(completed.stderr)["status"],
                    "blocked-safety",
                )

    def test_guard_live_consumer_rejects_malformed_or_oversized_receipt_bytes(
        self,
    ) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "malformed-live-consumer-review-workspace"
        )
        receipt_path, receipt = self.publish_prefix_receipt(
            prepared=prepared,
            base=base,
            head=head,
            name="malformed-prefix-receipt",
        )
        expected = str(receipt["receipt_sha256"])
        malformed_payloads = {
            "deep": b"[" * 300 + b"0" + b"]" * 300,
            "huge-integer": b'{"value":' + b"9" * 5_000 + b"}",
            "duplicate": b'{"value":1,"value":2}',
            "second-document": b"{}\n{}\n",
            "invalid-utf8": b'{"value":"\xff"}',
            "oversized": b" " * (64 * 1024 + 1),
        }
        for label, payload in malformed_payloads.items():
            with self.subTest(label=label):
                receipt_path.write_bytes(payload)
                receipt_path.chmod(0o600)
                completed = self.run_published_prefix_receipt_validation(
                    receipt_path=receipt_path,
                    prepared=prepared,
                    base=base,
                    head=head,
                    expected_receipt_sha256=expected,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stdout, "")
                self.assertEqual(
                    json.loads(completed.stderr)["status"],
                    "blocked-safety",
                )

    def test_live_consumer_retains_receipt_descriptor_across_validation(self) -> None:
        real_validator = named_lane_runtime.validate_sanitized_git_argv_prefix_receipt
        base, head = self.workspace_range()
        for replacement_mode in ("in-place", "name-replacement"):
            with self.subTest(replacement_mode=replacement_mode):
                prepared = review_workspace_runtime.prepare_workspace(
                    self.repo.resolve(),
                    self.root / f"{replacement_mode}-custody-review-workspace",
                    base,
                    head,
                )
                self._prefix_test_workspaces.append(prepared)
                receipt_path, receipt = self.publish_prefix_receipt(
                    prepared=prepared,
                    base=base,
                    head=head,
                    name=f"{replacement_mode}-custody-prefix-receipt",
                )

                def mutate_after_validation(
                    *args: object,
                    **kwargs: object,
                ) -> dict[str, object]:
                    validated = real_validator(*args, **kwargs)
                    if replacement_mode == "in-place":
                        receipt_path.write_bytes(b"{}\n")
                        receipt_path.chmod(0o600)
                    else:
                        replacement = receipt_path.with_name("replacement.json")
                        replacement.write_bytes(b"{}\n")
                        replacement.chmod(0o600)
                        os.replace(replacement, receipt_path)
                    return validated

                with (
                    mock.patch.object(
                        named_lane_runtime,
                        "validate_sanitized_git_argv_prefix_receipt",
                        side_effect=mutate_after_validation,
                    ),
                    self.assertRaisesRegex(
                        NamedLaneGuardError,
                        "receipt (?:content|identity or access policy) changed",
                    ),
                ):
                    validate_published_sanitized_git_argv_prefix_receipt(
                        receipt_file=receipt_path,
                        expected_receipt_sha256=str(receipt["receipt_sha256"]),
                        worktree=prepared.root,
                        base=base,
                        head=head,
                        git_executable=named_lane_runtime.resolve_git(),
                    )

    def test_live_consumer_accepts_benign_receipt_parent_entry_churn(self) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "parent-churn-live-consumer-review-workspace"
        )
        receipt_path, receipt = self.publish_prefix_receipt(
            prepared=prepared,
            base=base,
            head=head,
            name="parent-churn-prefix-receipt",
        )
        real_validator = named_lane_runtime.validate_sanitized_git_argv_prefix_receipt

        def churn_sibling(*args: object, **kwargs: object) -> dict[str, object]:
            validated = real_validator(*args, **kwargs)
            sibling = receipt_path.with_name("benign-sibling")
            sibling.write_text("churn\n", encoding="utf-8")
            sibling.unlink()
            return validated

        with mock.patch.object(
            named_lane_runtime,
            "validate_sanitized_git_argv_prefix_receipt",
            side_effect=churn_sibling,
        ):
            validated = validate_published_sanitized_git_argv_prefix_receipt(
                receipt_file=receipt_path,
                expected_receipt_sha256=str(receipt["receipt_sha256"]),
                worktree=prepared.root,
                base=base,
                head=head,
                git_executable=named_lane_runtime.resolve_git(),
            )
        self.assertEqual(validated, receipt)

    def test_guard_live_consumer_signal_is_structured_and_does_not_issue(
        self,
    ) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "signal-live-consumer-review-workspace"
        )
        receipt_path, receipt = self.publish_prefix_receipt(
            prepared=prepared,
            base=base,
            head=head,
            name="signal-prefix-receipt",
        )
        arguments = self.published_prefix_receipt_validation_argv(
            receipt_path=receipt_path,
            prepared=prepared,
            base=base,
            head=head,
            expected_receipt_sha256=str(receipt["receipt_sha256"]),
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                named_lane_runtime,
                "validate_sanitized_git_argv_prefix_receipt",
                side_effect=ForwardedSignal(signal.SIGTERM),
            ),
            mock.patch.object(
                named_lane_runtime,
                "sanitized_git_argv_prefix_receipt",
                side_effect=AssertionError("consumer must not invoke issuer"),
            ) as issuer,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(arguments)

        self.assertEqual(returncode, 128 + signal.SIGTERM)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {"status": "blocked-safety", "reason": "forwarded-signal"},
        )
        issuer.assert_not_called()

    def test_live_consumer_close_failures_preserve_active_primary_and_cause(
        self,
    ) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "primary-close-failure-live-consumer-review-workspace"
        )
        receipt_path, receipt = self.publish_prefix_receipt(
            prepared=prepared,
            base=base,
            head=head,
            name="primary-close-failure-prefix-receipt",
        )
        primary_cause = ValueError("synthetic active primary cause")
        primary = NamedLaneGuardError("synthetic active primary")
        primary.__cause__ = primary_cause
        primary.__suppress_context__ = True
        receipt_close = OSError("receipt real-close-then-error")
        parent_close = OSError("parent real-close-then-error")
        close_attempts: list[int] = []

        with (
            mock.patch.object(
                named_lane_runtime,
                "validate_sanitized_git_argv_prefix_receipt",
                side_effect=primary,
            ),
            mock.patch.object(
                named_lane_runtime,
                "_attempt_workspace_descriptor_closes",
                side_effect=self.descriptor_close_fault_injector(
                    (receipt_close, parent_close),
                    close_attempts,
                ),
            ),
            self.assertRaises(NamedLaneGuardError) as caught,
        ):
            validate_published_sanitized_git_argv_prefix_receipt(
                receipt_file=receipt_path,
                expected_receipt_sha256=str(receipt["receipt_sha256"]),
                worktree=prepared.root,
                base=base,
                head=head,
                git_executable=named_lane_runtime.resolve_git(),
            )

        self.assertIs(caught.exception, primary)
        self.assertIs(caught.exception.__cause__, primary_cause)
        self.assertEqual(len(close_attempts), 2)
        self.assertEqual(len(set(close_attempts)), 2)
        for descriptor in close_attempts:
            with self.assertRaises(OSError):
                os.fstat(descriptor)
        diagnostics = visible_exception_text(primary)
        self.assertIn("receipt descriptor close failed", diagnostics)
        self.assertIn("receipt real-close-then-error", diagnostics)
        self.assertIn("parent descriptor close failed", diagnostics)
        self.assertIn("parent real-close-then-error", diagnostics)

    def test_guard_live_consumer_close_failures_select_first_without_stdout(
        self,
    ) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "standalone-close-failure-live-consumer-review-workspace"
        )
        receipt_path, receipt = self.publish_prefix_receipt(
            prepared=prepared,
            base=base,
            head=head,
            name="standalone-close-failure-prefix-receipt",
        )
        arguments = self.published_prefix_receipt_validation_argv(
            receipt_path=receipt_path,
            prepared=prepared,
            base=base,
            head=head,
            expected_receipt_sha256=str(receipt["receipt_sha256"]),
        )
        close_attempts: list[int] = []
        receipt_close = OSError("receipt real-close-then-error")
        parent_close = OSError("parent real-close-then-error")
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            mock.patch.object(
                named_lane_runtime,
                "_attempt_workspace_descriptor_closes",
                side_effect=self.descriptor_close_fault_injector(
                    (receipt_close, parent_close),
                    close_attempts,
                ),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(arguments)

        self.assertEqual(returncode, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(len(close_attempts), 2)
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {
                "status": "blocked-safety",
                "reason": "receipt real-close-then-error",
            },
        )
        diagnostics = visible_exception_text(receipt_close)
        self.assertEqual(str(receipt_close), "receipt real-close-then-error")
        self.assertIn("receipt descriptor close failed", diagnostics)
        self.assertIn("parent descriptor close failed", diagnostics)
        self.assertIn("parent real-close-then-error", diagnostics)

    def test_guard_live_consumer_close_signal_attempts_parent_and_exits_143(
        self,
    ) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "close-signal-live-consumer-review-workspace"
        )
        receipt_path, receipt = self.publish_prefix_receipt(
            prepared=prepared,
            base=base,
            head=head,
            name="close-signal-prefix-receipt",
        )
        arguments = self.published_prefix_receipt_validation_argv(
            receipt_path=receipt_path,
            prepared=prepared,
            base=base,
            head=head,
            expected_receipt_sha256=str(receipt["receipt_sha256"]),
        )
        close_attempts: list[int] = []
        close_signal = ForwardedSignal(signal.SIGTERM)
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            mock.patch.object(
                named_lane_runtime,
                "_attempt_workspace_descriptor_closes",
                side_effect=self.descriptor_close_fault_injector(
                    (close_signal, None),
                    close_attempts,
                ),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(arguments)

        self.assertEqual(returncode, 128 + signal.SIGTERM)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(len(close_attempts), 2)
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {"status": "blocked-safety", "reason": "forwarded-signal"},
        )

    def test_codex_git_prefix_rejects_absent_or_wrong_range_workspace(self) -> None:
        base, head = self.workspace_range()
        git_executable = named_lane_runtime.resolve_git()
        with self.assertRaises(review_workspace_runtime.ReviewWorkspaceError) as absent:
            sanitized_git_argv_prefix_receipt(
                worktree=self.root / "absent-review-workspace",
                base=base,
                head=head,
                git_executable=git_executable,
            )
        self.assertEqual(absent.exception.reason, "invalid-path")
        with self.assertRaises(review_workspace_runtime.ReviewWorkspaceError):
            sanitized_git_argv_prefix_receipt(
                worktree=self.repo.resolve(),
                base=base,
                head=head,
                git_executable=git_executable,
            )

        prepared = review_workspace_runtime.prepare_workspace(
            self.repo.resolve(),
            self.root / "wrong-range-review-workspace",
            base,
            head,
        )
        self._prefix_test_workspaces.append(prepared)
        with self.assertRaises(review_workspace_runtime.ReviewWorkspaceError):
            sanitized_git_argv_prefix_receipt(
                worktree=prepared.root,
                base=head,
                head=head,
                git_executable=git_executable,
            )

    def test_codex_git_prefix_rejects_nonselected_git_path(self) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "wrong-git-review-workspace"
        )
        selected_git = named_lane_runtime.resolve_git()
        other_git = pathlib.Path("/usr/bin/git")
        if other_git == selected_git:
            other_git = pathlib.Path("/bin/false")
        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "differs from the fixed trusted Git path",
        ):
            sanitized_git_argv_prefix_receipt(
                worktree=prepared.root,
                base=base,
                head=head,
                git_executable=other_git,
            )

    def test_codex_git_prefix_rejects_malformed_git_version(self) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "malformed-version-review-workspace"
        )
        fake_git = self.root / "malformed-git"
        fake_git.write_text("#!/bin/sh\nprintf 'not git\\n'\n", encoding="utf-8")
        fake_git.chmod(0o700)
        with (
            mock.patch.object(named_lane_runtime, "resolve_git", return_value=fake_git),
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "returned a malformed version",
            ),
        ):
            sanitized_git_argv_prefix_receipt(
                worktree=prepared.root,
                base=base,
                head=head,
                git_executable=fake_git,
            )

    def test_codex_git_prefix_rejects_git_replacement_during_version_probe(
        self,
    ) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "git-replacement-review-workspace"
        )
        fake_git = self.root / "selected-git"
        replacement = self.root / "replacement-git"
        script = "#!/bin/sh\nprintf 'git version 2.53.0\\n'\n"
        fake_git.write_text(script, encoding="utf-8")
        replacement.write_text(script, encoding="utf-8")
        fake_git.chmod(0o700)
        replacement.chmod(0o700)
        real_capture = named_lane_runtime.run_bounded_capture

        def replace_after_capture(*args: object, **kwargs: object) -> object:
            captured = real_capture(*args, **kwargs)
            os.replace(replacement, fake_git)
            return captured

        with (
            mock.patch.object(named_lane_runtime, "resolve_git", return_value=fake_git),
            mock.patch.object(
                named_lane_runtime,
                "run_bounded_capture",
                side_effect=replace_after_capture,
            ),
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "changed during version validation",
            ),
        ):
            sanitized_git_argv_prefix_receipt(
                worktree=prepared.root,
                base=base,
                head=head,
                git_executable=fake_git,
            )

    def test_codex_git_prefix_version_probe_precedes_final_workspace_validation(
        self,
    ) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "version-workspace-race-review-workspace"
        )
        git_executable = named_lane_runtime.resolve_git()
        real_capture = named_lane_runtime.run_bounded_capture

        def mutate_workspace_after_version(*args: object, **kwargs: object) -> object:
            captured = real_capture(*args, **kwargs)
            (prepared.root / "tracked.txt").write_text(
                "mutated during version probe\n",
                encoding="utf-8",
            )
            return captured

        with (
            mock.patch.object(
                named_lane_runtime,
                "run_bounded_capture",
                side_effect=mutate_workspace_after_version,
            ),
            self.assertRaises(review_workspace_runtime.ReviewWorkspaceError),
        ):
            sanitized_git_argv_prefix_receipt(
                worktree=prepared.root,
                base=base,
                head=head,
                git_executable=git_executable,
            )

    def test_codex_git_prefix_version_probe_preserves_process_leak_error(self) -> None:
        git_executable = named_lane_runtime.resolve_git()
        identity = named_lane_runtime._capture_prefix_git_executable_identity(
            git_executable
        )
        process_error = ReviewProcessLeakError("synthetic version-probe leak")
        with (
            mock.patch.object(
                named_lane_runtime,
                "run_bounded_capture",
                side_effect=process_error,
            ),
            self.assertRaises(ReviewProcessLeakError) as caught,
        ):
            named_lane_runtime._validated_prefix_git_version(
                git_executable,
                git_executable.parent,
                identity,
            )
        self.assertIs(caught.exception, process_error)

    def test_codex_git_prefix_receipt_validator_rejects_closed_schema_and_type_drift(
        self,
    ) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "receipt-schema-review-workspace"
        )
        git_executable = named_lane_runtime.resolve_git()
        receipt = sanitized_git_argv_prefix_receipt(
            worktree=prepared.root,
            base=base,
            head=head,
            git_executable=git_executable,
        )

        def clone() -> dict[str, object]:
            return json.loads(json.dumps(receipt))

        def resign(value: dict[str, object]) -> None:
            value.pop("receipt_sha256", None)
            value["receipt_sha256"] = hashlib.sha256(
                json.dumps(
                    value,
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()

        extra = clone()
        extra["unexpected"] = "value"
        resign(extra)

        wrong_workspace_base = clone()
        workspace_receipt = wrong_workspace_base["workspace_validation_receipt"]
        assert isinstance(workspace_receipt, dict)
        workspace_receipt["base"] = head
        wrong_workspace_base["workspace_validation_receipt_sha256"] = hashlib.sha256(
            json.dumps(
                workspace_receipt,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        resign(wrong_workspace_base)

        coupled_resign = clone()
        coupled_workspace_receipt = coupled_resign["workspace_validation_receipt"]
        assert isinstance(coupled_workspace_receipt, dict)
        coupled_commit_count = coupled_workspace_receipt["commit_count"]
        assert isinstance(coupled_commit_count, int)
        coupled_workspace_receipt["commit_count"] = coupled_commit_count + 1
        coupled_resign["workspace_validation_receipt_sha256"] = hashlib.sha256(
            json.dumps(
                coupled_workspace_receipt,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        resign(coupled_resign)

        integer_executable = clone()
        integer_executable["git_executable"] = 7
        resign(integer_executable)

        identity_type_drift = clone()
        executable_identity = identity_type_drift["git_executable_identity"]
        assert isinstance(executable_identity, dict)
        target_identity = executable_identity["target"]
        assert isinstance(target_identity, dict)
        target_identity["inode"] = str(target_identity["inode"])
        resign(identity_type_drift)

        coupled_git_identity = clone()
        coupled_executable_identity = coupled_git_identity["git_executable_identity"]
        assert isinstance(coupled_executable_identity, dict)
        coupled_target_identity = coupled_executable_identity["target"]
        assert isinstance(coupled_target_identity, dict)
        coupled_inode = coupled_target_identity["inode"]
        assert isinstance(coupled_inode, int)
        coupled_target_identity["inode"] = coupled_inode + 1
        resign(coupled_git_identity)

        boolean_as_integer = clone()
        boolean_workspace_receipt = boolean_as_integer["workspace_validation_receipt"]
        assert isinstance(boolean_workspace_receipt, dict)
        boolean_workspace_receipt["commit_count"] = True
        boolean_as_integer["workspace_validation_receipt_sha256"] = hashlib.sha256(
            json.dumps(
                boolean_workspace_receipt,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        resign(boolean_as_integer)

        malformed_version = clone()
        malformed_version["git_version"] = "not git"
        malformed_version["git_version_stdout"] = "not git\n"
        malformed_version["git_version_stdout_sha256"] = hashlib.sha256(
            b"not git\n"
        ).hexdigest()
        resign(malformed_version)

        coupled_version = clone()
        coupled_version["git_version"] = "git version 99.0.0"
        coupled_version["git_version_stdout"] = "git version 99.0.0\n"
        coupled_version["git_version_stdout_sha256"] = hashlib.sha256(
            b"git version 99.0.0\n"
        ).hexdigest()
        resign(coupled_version)

        for label, candidate in (
            ("extra-key", extra),
            ("workspace-cross-field", wrong_workspace_base),
            ("coupled-resign", coupled_resign),
            ("executable-type", integer_executable),
            ("identity-type", identity_type_drift),
            ("coupled-git-identity", coupled_git_identity),
            ("bool-as-int", boolean_as_integer),
            ("version-grammar", malformed_version),
            ("coupled-version", coupled_version),
        ):
            with self.subTest(label=label), self.assertRaises(NamedLaneGuardError):
                validate_sanitized_git_argv_prefix_receipt(
                    candidate,
                    worktree=prepared.root,
                    base=base,
                    head=head,
                    git_executable=git_executable,
                )

    def test_codex_git_prefix_receipt_validator_rejects_stale_workspace(
        self,
    ) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "stale-receipt-review-workspace"
        )
        git_executable = named_lane_runtime.resolve_git()
        receipt = sanitized_git_argv_prefix_receipt(
            worktree=prepared.root,
            base=base,
            head=head,
            git_executable=git_executable,
        )
        (prepared.root / "tracked.txt").write_text(
            "stale receipt mutation\n",
            encoding="utf-8",
        )
        with self.assertRaises(review_workspace_runtime.ReviewWorkspaceError):
            validate_sanitized_git_argv_prefix_receipt(
                receipt,
                worktree=prepared.root,
                base=base,
                head=head,
                git_executable=git_executable,
            )

    def test_codex_git_prefix_receipt_validator_rejects_stale_git_identity(
        self,
    ) -> None:
        prepared, base, head = self.prepared_review_workspace(
            "stale-git-receipt-review-workspace"
        )
        fake_git = self.root / "receipt-selected-git"
        replacement = self.root / "receipt-replacement-git"
        script = "#!/bin/sh\nprintf 'git version 2.53.0\\n'\n"
        fake_git.write_text(script, encoding="utf-8")
        replacement.write_text(script, encoding="utf-8")
        fake_git.chmod(0o700)
        replacement.chmod(0o700)
        with mock.patch.object(
            named_lane_runtime,
            "resolve_git",
            return_value=fake_git,
        ):
            receipt = sanitized_git_argv_prefix_receipt(
                worktree=prepared.root,
                base=base,
                head=head,
                git_executable=fake_git,
            )
            os.replace(replacement, fake_git)
            with self.assertRaisesRegex(
                NamedLaneGuardError,
                "identity is stale",
            ):
                validate_sanitized_git_argv_prefix_receipt(
                    receipt,
                    worktree=prepared.root,
                    base=base,
                    head=head,
                    git_executable=fake_git,
                )

    def prepare_workspace_argv(
        self,
        destination: pathlib.Path,
        base: str,
        head: str,
    ) -> tuple[str, ...]:
        return (
            "prepare-workspace",
            "--source",
            str(self.repo.resolve()),
            "--worktree",
            str(destination),
            "--base",
            base,
            "--head",
            head,
        )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "workspace receipt handoff requires POSIX signal masks",
    )
    def test_prepare_workspace_cli_flushes_receipt_before_transferring_cleanup(
        self,
    ) -> None:
        base, head = self.workspace_range()
        destination = self.root / "flushed-workspace"

        class CountingStdout(io.StringIO):
            flush_calls = 0

            def flush(inner_self) -> None:
                super().flush()
                inner_self.flush_calls += 1

        stdout = CountingStdout()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                self.prepare_workspace_argv(destination, base, head)
            )

        self.assertEqual(returncode, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(stdout.flush_calls, 1)
        receipt = json.loads(stdout.getvalue())
        self.assertEqual(receipt["command"], "prepare-workspace")
        self.assertEqual(receipt["worktree"], str(destination))
        self.assertGreater(receipt["range_object_count"], 0)
        self.assertRegex(receipt["range_object_sha256"], r"\A[0-9a-f]{64}\Z")
        self.assertGreaterEqual(receipt["parent_support_object_count"], 0)
        self.assertRegex(
            receipt["parent_support_object_sha256"],
            r"\A[0-9a-f]{64}\Z",
        )
        self.assertEqual(receipt["shallow_bytes"], "")
        self.assertFalse((destination / ".git/shallow").exists())
        review_workspace_runtime.cleanup_workspace(
            destination,
            receipt["cleanup_token"],
        )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "workspace terminal failures require POSIX signal masks",
    )
    def test_prepare_workspace_cli_reports_direct_primary_remediation(self) -> None:
        base, head = self.workspace_range()
        source = self.root / "alternate-backed-cli-source"
        subprocess.run(
            (
                "git",
                "clone",
                "--quiet",
                "--shared",
                "--no-checkout",
                str(self.repo),
                str(source),
            ),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        destination = self.root / "alternate-backed-cli-workspace"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                (
                    "prepare-workspace",
                    "--source",
                    str(source.resolve()),
                    "--worktree",
                    str(destination),
                    "--base",
                    base,
                    "--head",
                    head,
                )
            )

        self.assertEqual(returncode, 2)
        self.assertEqual(stdout.getvalue(), "")
        failure = json.loads(stderr.getvalue())
        self.assertEqual(failure["status"], "blocked-safety")
        self.assertEqual(failure["reason"], "source-alternates-forbidden")
        self.assertEqual(failure["source_authority_policy"], "direct-primary-only")
        self.assertEqual(
            failure["remediation"],
            {
                "action": "use-independent-primary-object-store",
                "accepted_source_layouts": [
                    "ordinary-clone",
                    "linked-worktree",
                    "filesystem-reflink-or-cow-copy",
                ],
                "alternate_backed_clone": (
                    "recreate the source as an independent clone with --dissociate"
                ),
            },
        )
        self.assertFalse(destination.exists())

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "workspace receipt handoff requires POSIX signal masks",
    )
    def test_prepare_workspace_cli_publication_failures_roll_back_workspace(
        self,
    ) -> None:
        base, head = self.workspace_range()
        real_emit = named_lane_runtime._emit

        class PartialBrokenPipe(io.StringIO):
            committed = False
            failed = False

            def write(inner_self, payload: str) -> int:
                if not inner_self.failed:
                    inner_self.failed = True
                    super().write(payload[: max(1, len(payload) // 2)])
                    raise BrokenPipeError("simulated partial receipt write")
                return super().write(payload)

        class FlushBrokenPipe(io.StringIO):
            committed = False

            def flush(inner_self) -> None:
                raise BrokenPipeError("simulated receipt flush failure")

        cases: tuple[tuple[str, io.StringIO, str], ...] = (
            ("before-write", io.StringIO(), "simulated receipt write failure"),
            ("partial-write", PartialBrokenPipe(), "simulated partial receipt write"),
            ("flush", FlushBrokenPipe(), "simulated receipt flush failure"),
        )
        for label, stdout, expected_reason in cases:
            with self.subTest(label=label):
                destination = self.root / f"{label}-workspace"
                stderr = io.StringIO()

                def fail_before_write(
                    payload: dict[str, object],
                    *,
                    stream: object | None = None,
                ) -> None:
                    if (
                        label == "before-write"
                        and stream is None
                        and payload.get("command") == "prepare-workspace"
                    ):
                        raise BrokenPipeError("simulated receipt write failure")
                    real_emit(payload, stream=stream)

                with (
                    mock.patch.object(
                        named_lane_runtime,
                        "_emit",
                        side_effect=fail_before_write,
                    ),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    returncode = self.named_lane_main(
                        self.prepare_workspace_argv(destination, base, head)
                    )

                self.assertEqual(returncode, 2)
                failure = json.loads(stderr.getvalue())
                self.assertEqual(failure["status"], "blocked-safety")
                self.assertEqual(
                    failure["reason"], "workspace-receipt-publication-failed"
                )
                self.assertIn(expected_reason, failure["publication_reason"])
                self.assertEqual(failure["rollback_status"], "complete")
                self.assertFalse(destination.exists())
                if hasattr(stdout, "committed"):
                    self.assertFalse(stdout.committed)
                if label == "before-write":
                    self.assertEqual(stdout.getvalue(), "")
                elif label == "partial-write":
                    with self.assertRaises(json.JSONDecodeError):
                        json.loads(stdout.getvalue())
                else:
                    self.assertEqual(json.loads(stdout.getvalue())["status"], "ok")
                    self.assertNotEqual(returncode, 0)

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "workspace receipt handoff requires POSIX signal masks",
    )
    def test_prepare_workspace_cli_pending_return_signal_rolls_back_before_receipt(
        self,
    ) -> None:
        base, head = self.workspace_range()
        destination = self.root / "return-signal-workspace"
        real_prepare = review_workspace_runtime.prepare_workspace
        previous_handlers = {
            forwarded: signal.getsignal(forwarded)
            for forwarded in named_lane_runtime.forwarded_signals()
        }
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())

        def prepare_then_signal(*args: object, **kwargs: object) -> object:
            result = real_prepare(*args, **kwargs)
            signal.raise_signal(signal.SIGTERM)
            return result

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                named_lane_runtime,
                "prepare_workspace",
                side_effect=prepare_then_signal,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                self.prepare_workspace_argv(destination, base, head)
            )

        self.assertEqual(returncode, 128 + signal.SIGTERM)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {"status": "blocked-safety", "reason": "forwarded-signal"},
        )
        self.assertFalse(destination.exists())
        for forwarded, previous in previous_handlers.items():
            self.assertEqual(signal.getsignal(forwarded), previous)
        self.assertEqual(
            signal.pthread_sigmask(signal.SIG_BLOCK, set()),
            previous_mask,
        )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "workspace receipt handoff requires POSIX signal masks",
    )
    def test_prepare_workspace_cli_unquiesced_pack_signal_reports_retained_partial(
        self,
    ) -> None:
        base, head = self.workspace_range()
        destination = self.root / "unquiesced-pack-signal-workspace"

        def interrupt_after_process_start(
            *_args: object,
            **kwargs: object,
        ) -> object:
            for callback_name in ("on_process_starting", "on_process_started"):
                callback = kwargs[callback_name]
                assert callable(callback)
                callback()
            raise ForwardedSignal(signal.SIGTERM)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                review_workspace_runtime,
                "run_process",
                side_effect=interrupt_after_process_start,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                self.prepare_workspace_argv(destination, base, head)
            )

        self.assertEqual(returncode, 128 + signal.SIGTERM)
        self.assertEqual(stdout.getvalue(), "")
        payload_text = stderr.getvalue()
        payload = json.loads(payload_text)
        self.assertEqual(payload["status"], "blocked-safety")
        self.assertEqual(payload["reason"], "forwarded-signal")
        self.assertIs(payload["cleanup_unavailable_until_quiescent"], True)
        self.assertEqual(payload["retained_path"], str(destination))
        parent_metadata = destination.parent.stat()
        workspace_metadata = destination.stat(follow_symlinks=False)
        self.assertEqual(
            payload["parent_identity"],
            {
                "device": parent_metadata.st_dev,
                "inode": parent_metadata.st_ino,
                "uid": parent_metadata.st_uid,
            },
        )
        self.assertEqual(
            payload["workspace_identity"],
            {
                "device": workspace_metadata.st_dev,
                "inode": workspace_metadata.st_ino,
                "uid": workspace_metadata.st_uid,
            },
        )
        self.assertEqual(
            payload["recovery"],
            {
                "command": None,
                "argv": None,
                "argv_ready": False,
                "requires_quiescence_proof": True,
                "ordinary_cleanup_available": False,
                "instruction": payload["recovery"]["instruction"],
                "unavailable_reason": ("partial-recovery-process-identity-unavailable"),
            },
        )
        self.assertIn("do not invoke cleanup-workspace", payload_text.lower())
        self.assertNotIn("cleanup_token", payload_text)
        self.assertNotIn("--token", payload_text)
        self.assertFalse(
            (destination / ".git" / review_workspace_runtime.WORKSPACE_MARKER).exists()
        )
        self.assertEqual(
            len(tuple((destination / ".git/objects/pack").glob(".review-*.pack"))),
            1,
        )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "workspace receipt handoff requires POSIX signal masks",
    )
    def test_prepare_workspace_cli_signal_after_flush_keeps_delivered_workspace(
        self,
    ) -> None:
        base, head = self.workspace_range()
        destination = self.root / "post-flush-signal-workspace"

        class SignalAfterFlush(io.StringIO):
            injected = False

            def flush(inner_self) -> None:
                super().flush()
                if not inner_self.injected:
                    inner_self.injected = True
                    signal.raise_signal(signal.SIGTERM)

        stdout = SignalAfterFlush()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                self.prepare_workspace_argv(destination, base, head)
            )

        self.assertTrue(stdout.injected)
        self.assertEqual(returncode, 0)
        self.assertEqual(stderr.getvalue(), "")
        receipt = json.loads(stdout.getvalue())
        self.assertTrue(destination.is_dir())
        review_workspace_runtime.cleanup_workspace(
            destination,
            receipt["cleanup_token"],
        )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "workspace receipt handoff requires POSIX signal masks",
    )
    def test_prepare_workspace_cli_transient_restore_failure_keeps_success(
        self,
    ) -> None:
        base, head = self.workspace_range()
        destination = self.root / "transient-restore-workspace"
        real_prepare = review_workspace_runtime.prepare_workspace
        restore_attempts: list[int] = []
        captured_owner: list[object] = []

        def prepare_with_flaky_restore(
            *args: object,
            **kwargs: object,
        ) -> review_workspace_runtime.PreparedWorkspace:
            result = real_prepare(*args, **kwargs)
            owner = result._handoff_signal_mask
            assert owner is not None
            real_restore = owner.restore

            def flaky_restore(restore: object | None = None) -> None:
                restore_attempts.append(1)
                if len(restore_attempts) == 1:
                    raise OSError("simulated transient signal-mask restore failure")
                real_restore(restore)  # type: ignore[arg-type]

            owner.restore = flaky_restore  # type: ignore[method-assign]
            captured_owner.append(owner)
            return result

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                named_lane_runtime,
                "prepare_workspace",
                side_effect=prepare_with_flaky_restore,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                self.prepare_workspace_argv(destination, base, head)
            )

        self.assertEqual(returncode, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(len(restore_attempts), 2)
        owner = captured_owner[0]
        self.assertFalse(owner.active)  # type: ignore[attr-defined]
        receipt = json.loads(stdout.getvalue())
        review_workspace_runtime.cleanup_workspace(
            destination,
            receipt["cleanup_token"],
        )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "workspace receipt handoff requires POSIX signal masks",
    )
    def test_prepare_workspace_cli_post_flush_drain_failure_exits_success_only(
        self,
    ) -> None:
        base, head = self.workspace_range()
        destination = self.root / "post-flush-drain-failure-workspace"
        consume_calls = 0

        class TerminalExit(BaseException):
            def __init__(inner_self, returncode: int) -> None:
                inner_self.returncode = returncode

        def consume_with_post_flush_failure() -> signal.Signals | None:
            nonlocal consume_calls
            consume_calls += 1
            if consume_calls == 3:
                raise OSError("simulated post-flush pending-signal drain failure")
            return None

        def terminal_exit(returncode: int) -> None:
            raise TerminalExit(returncode)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                named_lane_runtime,
                "consume_pending_forwarded_signal",
                side_effect=consume_with_post_flush_failure,
            ),
            mock.patch.object(
                named_lane_runtime,
                "_terminal_process_exit",
                side_effect=terminal_exit,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
            self.assertRaises(TerminalExit) as caught,
        ):
            self.named_lane_main(self.prepare_workspace_argv(destination, base, head))

        self.assertEqual(caught.exception.returncode, 0)
        self.assertEqual(stderr.getvalue(), "")
        receipt = json.loads(stdout.getvalue())
        self.assertTrue(destination.is_dir())
        review_workspace_runtime.cleanup_workspace(
            destination,
            receipt["cleanup_token"],
        )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "workspace receipt handoff requires POSIX signal masks",
    )
    def test_prepare_workspace_cli_cleanup_failure_reports_bound_recovery(
        self,
    ) -> None:
        base, head = self.workspace_range()
        destination = self.root / "retained-publication-workspace"
        real_prepare = review_workspace_runtime.prepare_workspace
        real_emit = named_lane_runtime._emit
        prepared_results: list[review_workspace_runtime.PreparedWorkspace] = []
        restore_attempts: list[int] = []

        def capture_prepare(
            *args: object,
            **kwargs: object,
        ) -> review_workspace_runtime.PreparedWorkspace:
            result = real_prepare(*args, **kwargs)
            owner = result._handoff_signal_mask
            assert owner is not None

            def fail_restore(_restore: object | None = None) -> None:
                restore_attempts.append(1)
                raise OSError("simulated signal-mask restore failure")

            owner.restore = fail_restore  # type: ignore[method-assign]
            prepared_results.append(result)
            return result

        def fail_receipt(
            payload: dict[str, object],
            *,
            stream: object | None = None,
        ) -> None:
            if stream is None and payload.get("command") == "prepare-workspace":
                raise BrokenPipeError("simulated publication failure")
            real_emit(payload, stream=stream)

        def fail_cleanup(*_args: object, **_kwargs: object) -> object:
            raise review_workspace_runtime.ReviewWorkspaceError(
                "synthetic-cleanup-failure",
                "simulated identity-bound cleanup failure",
            )

        class CountingStderr(io.StringIO):
            flush_calls = 0
            signal_injected = False

            def flush(inner_self) -> None:
                super().flush()
                inner_self.flush_calls += 1
                if not inner_self.signal_injected:
                    inner_self.signal_injected = True
                    signal.raise_signal(signal.SIGTERM)

        stdout = io.StringIO()
        stderr = CountingStderr()
        with (
            mock.patch.object(
                named_lane_runtime,
                "prepare_workspace",
                side_effect=capture_prepare,
            ),
            mock.patch.object(
                named_lane_runtime,
                "cleanup_workspace",
                side_effect=fail_cleanup,
            ),
            mock.patch.object(named_lane_runtime, "_emit", side_effect=fail_receipt),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                self.prepare_workspace_argv(destination, base, head)
            )

        self.assertEqual(returncode, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.flush_calls, 1)
        self.assertTrue(stderr.signal_injected)
        self.assertEqual(len(restore_attempts), 2)
        failure = json.loads(stderr.getvalue())
        prepared = prepared_results[0]
        assert prepared._handoff_signal_mask is not None
        self.assertFalse(prepared._handoff_signal_mask.active)
        self.assertEqual(
            set(failure),
            {
                "status",
                "reason",
                "primary_reason",
                "cleanup_reason",
                "cleanup_token_sha256",
                "parent_identity",
                "workspace_identity",
                "partial_recovery_control",
                "workspace_state",
                "owner_process",
                "active_process",
                "cleanup_unavailable_until_quiescent",
                "recovery",
                "retained_path",
            },
        )
        self.assertEqual(failure["reason"], "workspace-publication-rollback-incomplete")
        self.assertEqual(failure["primary_reason"], "simulated publication failure")
        self.assertEqual(failure["cleanup_reason"], "synthetic-cleanup-failure")
        self.assertEqual(failure["retained_path"], str(destination))
        self.assertEqual(
            failure["cleanup_token_sha256"],
            prepared.cleanup_token_sha256,
        )
        self.assertNotIn(prepared.cleanup_token, stderr.getvalue())
        self.assertEqual(
            failure["recovery"]["argv"],
            [
                "recover-partial-workspace",
                "--control-file",
                failure["partial_recovery_control"]["path"],
                "--control-sha256",
                failure["partial_recovery_control"]["sha256"],
            ],
        )
        self.assertTrue(failure["recovery"]["argv_ready"])
        self.assertNotIn("<", " ".join(failure["recovery"]["argv"]))
        with mock.patch.object(
            review_workspace_runtime,
            "_process_start_identity",
            side_effect=ProcessLookupError,
        ):
            recovered = review_workspace_runtime.recover_partial_workspace(
                pathlib.Path(failure["partial_recovery_control"]["path"]),
                failure["partial_recovery_control"]["sha256"],
            )
        self.assertEqual(recovered.cleanup_status, "payload-removed")

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "workspace receipt handoff requires POSIX signal masks",
    )
    def test_publication_rollback_recovery_roundtrips_from_serialized_child_result(
        self,
    ) -> None:
        base, head = self.workspace_range()
        destination = self.root / "serialized-publication-recovery"
        child_script = self.root / "publication_failure_child.py"
        child_script.write_text(
            "\n".join(
                (
                    "import pathlib",
                    "import sys",
                    f"sys.path.insert(0, {str(SCRIPTS)!r})",
                    "from review_runtime import named_lane as runtime",
                    "from review_runtime.review_workspace import ReviewWorkspaceError",
                    "real_emit = runtime._emit",
                    "def fail_emit(payload, *, stream=None):",
                    "    if stream is None and payload.get('command') == 'prepare-workspace':",
                    "        raise BrokenPipeError('fixture serialized publication failure')",
                    "    return real_emit(payload, stream=stream)",
                    "def fail_cleanup(*args, **kwargs):",
                    "    raise ReviewWorkspaceError('fixture-rollback-failure', 'fixture rollback failure')",
                    "runtime._emit = fail_emit",
                    "runtime.cleanup_workspace = fail_cleanup",
                    "raise SystemExit(runtime.main((",
                    "    'prepare-workspace',",
                    f"    '--source', {str(self.repo)!r},",
                    f"    '--worktree', {str(destination)!r},",
                    f"    '--base', {base!r},",
                    f"    '--head', {head!r},",
                    ")))",
                    "",
                )
            ),
            encoding="utf-8",
        )
        child = subprocess.run(
            (
                str(pathlib.Path(sys.executable).resolve()),
                "-I",
                "-B",
                "-S",
                str(child_script),
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
        self.assertEqual(child.returncode, 2, child.stderr)
        self.assertEqual(child.stdout, "")
        failure = json.loads(child.stderr)
        self.assertEqual(
            failure["reason"],
            "workspace-publication-rollback-incomplete",
        )
        recovery = failure["recovery"]
        self.assertTrue(recovery["argv_ready"])
        self.assertNotIn("<cleanup-token", child.stderr)
        control_path = pathlib.Path(failure["partial_recovery_control"]["path"])
        control_metadata = control_path.stat(follow_symlinks=False)
        self.assertEqual(stat.S_IMODE(control_metadata.st_mode), 0o600)
        self.assertEqual(control_metadata.st_nlink, 1)

        guard = SCRIPTS / "named_lane_guard"
        recovered = subprocess.run(
            (
                str(pathlib.Path(sys.executable).resolve()),
                "-I",
                "-B",
                "-S",
                str(guard),
                *recovery["argv"],
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        receipt = json.loads(recovered.stdout)
        self.assertEqual(receipt["command"], "recover-partial-workspace")
        self.assertEqual(receipt["cleanup_status"], "payload-removed")

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "workspace receipt handoff requires POSIX signal masks",
    )
    def test_prepare_workspace_cli_cleanup_failure_does_not_claim_replaced_path(
        self,
    ) -> None:
        base, head = self.workspace_range()
        destination = self.root / "replaced-publication-workspace"
        retained = self.root / "identity-bound-original-workspace"
        real_prepare = review_workspace_runtime.prepare_workspace
        real_emit = named_lane_runtime._emit
        prepared_results: list[review_workspace_runtime.PreparedWorkspace] = []

        def capture_prepare(
            *args: object,
            **kwargs: object,
        ) -> review_workspace_runtime.PreparedWorkspace:
            result = real_prepare(*args, **kwargs)
            prepared_results.append(result)
            return result

        def fail_receipt(
            payload: dict[str, object],
            *,
            stream: object | None = None,
        ) -> None:
            if stream is None and payload.get("command") == "prepare-workspace":
                raise BrokenPipeError("simulated publication failure")
            real_emit(payload, stream=stream)

        def replace_before_cleanup(*_args: object, **_kwargs: object) -> object:
            destination.rename(retained)
            destination.mkdir(mode=0o700)
            raise review_workspace_runtime.ReviewWorkspaceError(
                "workspace-identity-mismatch",
                "simulated replacement before cleanup",
            )

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                named_lane_runtime,
                "prepare_workspace",
                side_effect=capture_prepare,
            ),
            mock.patch.object(
                named_lane_runtime,
                "cleanup_workspace",
                side_effect=replace_before_cleanup,
            ),
            mock.patch.object(named_lane_runtime, "_emit", side_effect=fail_receipt),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                self.prepare_workspace_argv(destination, base, head)
            )

        self.assertEqual(returncode, 2)
        failure = json.loads(stderr.getvalue())
        self.assertEqual(failure["retained_path"], str(retained))
        self.assertEqual(
            failure["workspace_identity"]["inode"],
            prepared_results[0].workspace_identity[1],
        )
        self.assertTrue(failure["recovery"]["argv_ready"])
        self.assertEqual(
            failure["recovery"]["argv"][0],
            "recover-partial-workspace",
        )
        with mock.patch.object(
            review_workspace_runtime,
            "_process_start_identity",
            side_effect=ProcessLookupError,
        ):
            recovered = review_workspace_runtime.recover_partial_workspace(
                pathlib.Path(failure["partial_recovery_control"]["path"]),
                failure["partial_recovery_control"]["sha256"],
            )
        self.assertEqual(recovered.root, retained)

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "workspace receipt handoff requires POSIX signal masks",
    )
    def test_workspace_failure_envelope_write_failures_exit_without_mask_leak(
        self,
    ) -> None:
        base, head = self.workspace_range()
        real_prepare = review_workspace_runtime.prepare_workspace
        previous_handlers = {
            forwarded: signal.getsignal(forwarded)
            for forwarded in named_lane_runtime.forwarded_signals()
        }
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())

        class TerminalExit(BaseException):
            def __init__(inner_self, returncode: int) -> None:
                inner_self.returncode = returncode

        class ReceiptBrokenPipe(io.StringIO):
            def write(inner_self, _payload: str) -> int:
                raise BrokenPipeError("simulated stdout receipt failure")

        class PartialStderr(io.StringIO):
            failed = False

            def write(inner_self, payload: str) -> int:
                if not inner_self.failed:
                    inner_self.failed = True
                    super().write(payload[: max(1, len(payload) // 2)])
                    raise BrokenPipeError("simulated partial stderr write failure")
                return super().write(payload)

        class FlushStderr(io.StringIO):
            def flush(inner_self) -> None:
                raise BrokenPipeError("simulated stderr flush failure")

        def terminal_exit(returncode: int) -> None:
            raise TerminalExit(returncode)

        def fail_cleanup(*_args: object, **_kwargs: object) -> object:
            raise review_workspace_runtime.ReviewWorkspaceError(
                "synthetic-cleanup-failure",
                "simulated retained rollback target",
            )

        for label, stderr in (
            ("partial", PartialStderr()),
            ("flush", FlushStderr()),
        ):
            with self.subTest(label=label):
                destination = self.root / f"stderr-{label}-workspace"
                stdout = ReceiptBrokenPipe()
                prepared_results: list[review_workspace_runtime.PreparedWorkspace] = []

                def capture_prepare(
                    *args: object,
                    **kwargs: object,
                ) -> review_workspace_runtime.PreparedWorkspace:
                    result = real_prepare(*args, **kwargs)
                    prepared_results.append(result)
                    return result

                with (
                    mock.patch.object(
                        named_lane_runtime,
                        "prepare_workspace",
                        side_effect=capture_prepare,
                    ),
                    mock.patch.object(
                        named_lane_runtime,
                        "cleanup_workspace",
                        side_effect=fail_cleanup,
                    ),
                    mock.patch.object(
                        named_lane_runtime,
                        "_terminal_process_exit",
                        side_effect=terminal_exit,
                    ),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                    self.assertRaises(TerminalExit) as caught,
                ):
                    self.named_lane_main(
                        self.prepare_workspace_argv(destination, base, head)
                    )

                self.assertEqual(caught.exception.returncode, 2)
                self.assertTrue(destination.is_dir())
                if label == "partial":
                    with self.assertRaises(json.JSONDecodeError):
                        json.loads(stderr.getvalue())
                    self.assertEqual(stderr.getvalue().count("\n"), 0)
                else:
                    self.assertEqual(
                        json.loads(stderr.getvalue())["reason"],
                        "workspace-publication-rollback-incomplete",
                    )
                    self.assertEqual(len(stderr.getvalue().splitlines()), 1)
                for forwarded, previous in previous_handlers.items():
                    self.assertEqual(signal.getsignal(forwarded), previous)
                self.assertEqual(
                    signal.pthread_sigmask(signal.SIG_BLOCK, set()),
                    previous_mask,
                )
                matching_controls = []
                for candidate in destination.parent.glob(
                    f"{review_workspace_runtime.PARTIAL_RECOVERY_PREFIX}*.json"
                ):
                    payload = json.loads(candidate.read_bytes())
                    if payload.get("worktree") == str(destination):
                        matching_controls.append(candidate)
                self.assertEqual(len(matching_controls), 1)
                control_path = matching_controls[0]
                control_digest = hashlib.sha256(control_path.read_bytes()).hexdigest()
                with mock.patch.object(
                    review_workspace_runtime,
                    "_process_start_identity",
                    side_effect=ProcessLookupError,
                ):
                    recovered = review_workspace_runtime.recover_partial_workspace(
                        control_path,
                        control_digest,
                    )
                self.assertEqual(recovered.cleanup_status, "payload-removed")

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "workspace receipt handoff requires POSIX signal masks",
    )
    def test_workspace_terminal_persistent_restore_failure_exits_with_published_rc(
        self,
    ) -> None:
        probe = """
import signal
import sys

sys.path.insert(0, sys.argv[1])
from review_runtime import named_lane
from review_runtime.common import ForwardedSignalMaskOwner

previous = signal.pthread_sigmask(
    signal.SIG_BLOCK,
    set(named_lane.forwarded_signals()),
)
owner = ForwardedSignalMaskOwner(previous_mask=previous, active=True)

def fail_restore(_restore=None):
    raise OSError("persistent owner restore failure")

def fail_direct(_previous_mask):
    raise OSError("persistent direct restore failure")

owner.restore = fail_restore
named_lane._direct_restore_workspace_signal_mask = fail_direct
state = named_lane._StructuredSignalState()
if sys.argv[2] == "success":
    named_lane._emit_workspace_terminal_receipt(
        {"status": "ok", "command": "fixture", "cleanup_token": "fixture-token"},
        state,
        handoff_owner=owner,
    )
else:
    named_lane._emit_structured_terminal_failure(
        {"status": "blocked-safety", "reason": "fixture"},
        state,
        returncode=7,
        handoff_owner=owner,
    )
raise AssertionError("terminal publisher returned with an active mask owner")
"""
        for mode, expected_returncode in (("success", 0), ("failure", 7)):
            with self.subTest(mode=mode):
                completed = subprocess.run(
                    (
                        sys.executable,
                        "-B",
                        "-c",
                        probe,
                        str(SCRIPTS),
                        mode,
                    ),
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(completed.returncode, expected_returncode)
                if mode == "success":
                    self.assertEqual(completed.stderr, "")
                    self.assertEqual(
                        json.loads(completed.stdout),
                        {
                            "status": "ok",
                            "command": "fixture",
                            "cleanup_token": "fixture-token",
                        },
                    )
                else:
                    self.assertEqual(completed.stdout, "")
                    self.assertEqual(
                        json.loads(completed.stderr),
                        {"status": "blocked-safety", "reason": "fixture"},
                    )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "workspace receipt handoff requires POSIX signal masks",
    )
    def test_workspace_failure_handler_install_failure_restores_before_exit(
        self,
    ) -> None:
        base, head = self.workspace_range()
        destination = self.root / "stderr-handler-install-workspace"
        previous_handlers = {
            forwarded: signal.getsignal(forwarded)
            for forwarded in named_lane_runtime.forwarded_signals()
        }
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        real_install = named_lane_runtime._install_post_terminal_signal_handlers
        install_calls = 0

        class TerminalExit(BaseException):
            def __init__(inner_self, returncode: int) -> None:
                inner_self.returncode = returncode

        class ReceiptBrokenPipe(io.StringIO):
            def write(inner_self, _payload: str) -> int:
                raise BrokenPipeError("simulated stdout receipt failure")

        def install_then_fail() -> list[signal.Signals]:
            nonlocal install_calls
            install_calls += 1
            if install_calls == 2:
                raise OSError("simulated terminal handler installation failure")
            return real_install()

        def terminal_exit(returncode: int) -> None:
            raise TerminalExit(returncode)

        stdout = ReceiptBrokenPipe()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                named_lane_runtime,
                "_install_post_terminal_signal_handlers",
                side_effect=install_then_fail,
            ),
            mock.patch.object(
                named_lane_runtime,
                "_terminal_process_exit",
                side_effect=terminal_exit,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
            self.assertRaises(TerminalExit) as caught,
        ):
            self.named_lane_main(self.prepare_workspace_argv(destination, base, head))

        self.assertEqual(caught.exception.returncode, 2)
        self.assertEqual(install_calls, 2)
        self.assertEqual(stderr.getvalue(), "")
        self.assertFalse(destination.exists())
        for forwarded, previous in previous_handlers.items():
            self.assertEqual(signal.getsignal(forwarded), previous)
        self.assertEqual(
            signal.pthread_sigmask(signal.SIG_BLOCK, set()),
            previous_mask,
        )

    def test_workspace_publication_recovery_accepts_only_identity_bound_quarantine(
        self,
    ) -> None:
        base, head = self.workspace_range()
        recovery_parent = self.root / "recovery-parent"
        recovery_parent.mkdir(mode=0o700)
        prepared = review_workspace_runtime.prepare_workspace(
            self.repo.resolve(),
            recovery_parent / "quarantine-recovery-workspace",
            base,
            head,
        )
        quarantine = recovery_parent / ".quarantine-recovery-workspace.cleanup-fixture"
        prepared.root.rename(quarantine)
        try:
            cleanup_error = review_workspace_runtime.ReviewWorkspaceError(
                "workspace-cleanup-incomplete",
                "fixture retained quarantine",
                details={"retained_path": str(quarantine)},
            )
            self.assertEqual(
                named_lane_runtime._prepared_workspace_retained_path(
                    prepared,
                    cleanup_error,
                ),
                str(quarantine),
            )

            replacement = prepared.root
            replacement.mkdir(mode=0o700)
            replaced_error = review_workspace_runtime.ReviewWorkspaceError(
                "workspace-cleanup-incomplete",
                "fixture unverified replacement",
                details={"retained_path": str(replacement)},
            )
            self.assertEqual(
                named_lane_runtime._prepared_workspace_retained_path(
                    prepared,
                    replaced_error,
                ),
                str(quarantine),
            )
            replacement.rmdir()

            quarantine.chmod(0o755)
            self.assertIsNone(
                named_lane_runtime._prepared_workspace_retained_path(
                    prepared,
                    cleanup_error,
                )
            )
            quarantine.chmod(0o700)

            recovery_parent.chmod(0o755)
            self.assertIsNone(
                named_lane_runtime._prepared_workspace_retained_path(
                    prepared,
                    cleanup_error,
                )
            )
            recovery_parent.chmod(0o700)

            original_parent = recovery_parent.with_name("recovery-parent-original")
            recovery_parent.rename(original_parent)
            recovery_parent.mkdir(mode=0o700)
            moved_quarantine = recovery_parent / quarantine.name
            (original_parent / quarantine.name).rename(moved_quarantine)
            try:
                parent_swap_error = review_workspace_runtime.ReviewWorkspaceError(
                    "workspace-cleanup-incomplete",
                    "fixture parent replacement",
                    details={"retained_path": str(moved_quarantine)},
                )
                self.assertIsNone(
                    named_lane_runtime._prepared_workspace_retained_path(
                        prepared,
                        parent_swap_error,
                    )
                )
            finally:
                moved_quarantine.rename(original_parent / quarantine.name)
                recovery_parent.rmdir()
                original_parent.rename(recovery_parent)
        finally:
            quarantine.rename(prepared.root)
            review_workspace_runtime.cleanup_workspace(
                prepared.root,
                prepared.cleanup_token,
            )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "workspace receipt handoff requires POSIX signal masks",
    )
    def test_validate_and_cleanup_cli_keep_flushed_terminal_receipts(self) -> None:
        base, head = self.workspace_range()
        prepared = review_workspace_runtime.prepare_workspace(
            self.repo.resolve(),
            self.root / "terminal-receipt-workspace",
            base,
            head,
        )
        real_cleanup = review_workspace_runtime.cleanup_workspace

        def cleanup_then_signal(*args: object, **kwargs: object) -> object:
            result = real_cleanup(*args, **kwargs)
            signal.raise_signal(signal.SIGTERM)
            return result

        class SignalAfterFlush(io.StringIO):
            injected = False

            def flush(inner_self) -> None:
                super().flush()
                if not inner_self.injected:
                    inner_self.injected = True
                    signal.raise_signal(signal.SIGINT)

        commands = (
            (
                "validate-workspace",
                (
                    "validate-workspace",
                    "--worktree",
                    str(prepared.root),
                    "--base",
                    base,
                    "--head",
                    head,
                ),
            ),
            (
                "cleanup-workspace",
                (
                    "cleanup-workspace",
                    "--worktree",
                    str(prepared.root),
                    "--token",
                    prepared.cleanup_token,
                ),
            ),
        )
        for command, argv in commands:
            with self.subTest(command=command):
                stdout = SignalAfterFlush()
                stderr = io.StringIO()
                with contextlib.ExitStack() as stack:
                    if command == "cleanup-workspace":
                        stack.enter_context(
                            mock.patch.object(
                                named_lane_runtime,
                                "cleanup_workspace",
                                side_effect=cleanup_then_signal,
                            )
                        )
                    stack.enter_context(contextlib.redirect_stdout(stdout))
                    stack.enter_context(contextlib.redirect_stderr(stderr))
                    returncode = self.named_lane_main(argv)
                self.assertTrue(stdout.injected)
                self.assertEqual(returncode, 0)
                self.assertEqual(stderr.getvalue(), "")
                self.assertEqual(json.loads(stdout.getvalue())["command"], command)
        self.assertFalse(prepared.root.exists())

    def bind_formal_validator_range(self, base: str, head: str) -> None:
        info = self.repo / ".git" / "info"
        info.mkdir(mode=0o700, exist_ok=True)
        info.chmod(0o700)
        for ref_name, object_id in (
            (MATERIALIZER_BASE_REF, base),
            (MATERIALIZER_HEAD_REF, head),
        ):
            ref_path = self.repo / ".git" / pathlib.PurePosixPath(ref_name)
            ref_path.parent.mkdir(parents=True, exist_ok=True)
            ref_path.write_bytes(f"{object_id}\n".encode("ascii"))
        shallow = self.repo / ".git" / "shallow"
        shallow.write_bytes(f"{base}\n".encode("ascii"))
        shallow.chmod(0o600)

    def validate_repo(
        self,
        head: str,
        *,
        base: str | None = None,
        guidance_paths: tuple[str, ...] = (),
    ) -> object:
        frozen_base = head if base is None else base
        self.bind_formal_validator_range(frozen_base, head)
        return validate_worktree(
            self.repo.resolve(),
            frozen_base,
            head,
            guidance_paths,
        )

    def make_executable(
        self,
        source: str,
        *,
        version: str = "2.1.212",
    ) -> pathlib.Path:
        executable = self.root / f"command-{time.monotonic_ns()}.py"
        executable.write_text(
            f"#!{sys.executable}\n{source}",
            encoding="utf-8",
        )
        executable.chmod(0o755)
        resolved = executable.resolve()
        self.write_preflight_result(resolved, version=version)
        return resolved

    def make_claude_home(self) -> pathlib.Path:
        home = self.root / f"claude-home-{time.monotonic_ns()}"
        session_env = home / ".claude" / "session-env"
        session_env.mkdir(parents=True, mode=0o755)
        home.chmod(0o700)
        (home / ".claude").chmod(0o700)
        session_env.chmod(0o755)
        return home

    def claude_account(self, home: pathlib.Path) -> mock.Mock:
        return mock.Mock(
            pw_dir=str(home),
            pw_name="named-lane-test",
            pw_shell="/bin/sh",
        )

    def preflight_result_path(self, executable: pathlib.Path) -> pathlib.Path:
        return executable.with_name(f"{executable.name}.preflight.json")

    def write_preflight_result(
        self,
        executable: pathlib.Path,
        *,
        version: str = "2.1.212",
    ) -> pathlib.Path:
        metadata = executable.lstat()
        checksum = hashlib.sha256(executable.read_bytes()).hexdigest()
        evidence = {
            "capability_contract": {
                "required_options": list(
                    named_lane_runtime._claude_direct_required_options(
                        named_lane_runtime.parse_compatible_release_version(version)
                    )
                ),
                "status": "accepted",
            },
            "classification": "accepted",
            "compatible_version_range": ">=2.1.211,<3.0.0",
            "declared_version": version,
            "identity": {
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "file_type": stat.S_IFMT(metadata.st_mode),
                "mode": metadata.st_mode,
                "nlink": metadata.st_nlink,
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "size": metadata.st_size,
                "mtime_ns": metadata.st_mtime_ns,
                "ctime_ns": metadata.st_ctime_ns,
            },
            "observed_version": version,
            "publisher_verification": {
                "artifact_size": metadata.st_size,
                "binary": "claude",
                "checksum": checksum,
                "manifest_url": "https://example.invalid/manifest.json",
                "platform": "test-platform",
                "release_version": version,
                "signature_url": "https://example.invalid/manifest.sig",
                "signer_fingerprint": "test-fingerprint",
            },
            "reason": "compatible-version-selected",
            "resolved_path": str(executable),
            "selected_version": version,
            "source": "explicit-override",
            "stream_contract": {},
        }
        path = self.preflight_result_path(executable)
        path.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
        path.chmod(0o600)
        return path

    def copy_guard_bundle(self) -> tuple[pathlib.Path, pathlib.Path]:
        bundle = self.root / f"bundle-{time.monotonic_ns()}"
        scripts = bundle / "scripts"
        scripts.mkdir(parents=True)
        guard = scripts / "named_lane_guard"
        shutil.copy2(SCRIPTS / "named_lane_guard", guard)
        shutil.copy2(SCRIPTS / "named_claude_preflight", scripts)
        shutil.copy2(SCRIPTS / "validate_claude_stream.py", scripts)
        shutil.copytree(
            SCRIPTS / "review_runtime",
            scripts / "review_runtime",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        references = bundle / "references"
        references.mkdir()
        shutil.copy2(
            SCRIPTS.parent / "references/claude-stream-compatibility.json",
            references,
        )
        shutil.copy2(
            SCRIPTS.parent / "references/claude-2.1.212-stream-schema.json",
            references,
        )
        shutil.copy2(
            SCRIPTS.parent / "references/claude-stream-schema.json",
            references,
        )
        return scripts, guard

    @staticmethod
    def stream_companion_paths(scripts: pathlib.Path) -> tuple[pathlib.Path, ...]:
        return (
            scripts.parent / "references/claude-stream-compatibility.json",
            scripts.parent / "references/claude-2.1.212-stream-schema.json",
            scripts.parent / "references/claude-stream-schema.json",
            scripts / "review_runtime/claude_capabilities.py",
        )

    def isolated_guard_command(
        self,
        guard: pathlib.Path,
        *arguments: str,
        python_executable: pathlib.Path | None = None,
        include_prepared_source_authority: bool = True,
    ) -> tuple[str, ...]:
        if python_executable is None:
            python_executable = pathlib.Path(sys.executable).resolve()
        self.assertTrue(python_executable.is_absolute())
        self.assertTrue(python_executable.is_file())
        guarded_arguments = list(arguments)
        if (
            include_prepared_source_authority
            and guarded_arguments
            and guarded_arguments[0] == "run-claude"
            and "--source-authority-binding-json" not in guarded_arguments
            and "--source-worktree" in guarded_arguments
        ):
            source_index = guarded_arguments.index("--source-worktree") + 1
            source = pathlib.Path(guarded_arguments[source_index])
            receipt = self.prepared_source_authority_receipt(source)
            canonical_binding = (
                review_workspace_runtime.canonical_source_authority_binding_bytes(
                    receipt["source_authority_binding"]
                )
            )
            self.assertEqual(
                hashlib.sha256(canonical_binding).hexdigest(),
                receipt["source_authority_binding_sha256"],
            )
            guarded_arguments[1:1] = (
                "--source-authority-binding-json",
                canonical_binding.decode("utf-8"),
                "--source-authority-binding-sha256",
                receipt["source_authority_binding_sha256"],
            )
        return (
            str(python_executable),
            "-I",
            "-B",
            "-S",
            str(guard),
            *guarded_arguments,
        )

    def install_unchecked_pyc(
        self,
        source_path: pathlib.Path,
        marker: pathlib.Path,
        *,
        label: str,
    ) -> pathlib.Path:
        malicious_source = self.root / f"malicious-{label}-{time.monotonic_ns()}.py"
        malicious_source.write_text(
            "import pathlib\n"
            f"pathlib.Path({str(marker)!r}).write_text('loaded')\n"
            f"raise RuntimeError('malicious {label} pyc executed')\n",
            encoding="utf-8",
        )
        # Guard subprocesses use -I, so they ignore an ambient PYTHONPYCACHEPREFIX.
        with mock.patch.object(sys, "pycache_prefix", None):
            cache_path = pathlib.Path(
                importlib.util.cache_from_source(
                    str(source_path),
                    optimization="",
                )
            )
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        py_compile.compile(
            str(malicious_source),
            cfile=str(cache_path),
            doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
            optimize=0,
        )
        return cache_path

    def guard_probe_command(
        self,
        guard: pathlib.Path,
        body: str,
        *,
        guard_arguments: tuple[str, ...] = (),
    ) -> tuple[str, ...]:
        probe = self.root / f"guard-probe-{time.monotonic_ns()}.py"
        probe.write_text(
            "import pathlib\n"
            "import sys\n"
            f"guard = pathlib.Path({str(guard)!r})\n"
            f"sys.argv = [str(guard), *{guard_arguments!r}]\n"
            "source = guard.read_bytes()\n"
            "namespace = {\n"
            "    '__name__': '_named_lane_guard_probe',\n"
            "    '__file__': str(guard),\n"
            "}\n"
            "exec(compile(source, str(guard), 'exec'), namespace)\n"
            f"{body}",
            encoding="utf-8",
        )
        return (
            str(pathlib.Path(sys.executable).resolve()),
            "-I",
            "-B",
            "-S",
            str(probe),
        )

    def guard_failure_probe_command(
        self,
        guard: pathlib.Path,
        *,
        guard_arguments: tuple[str, ...] = (),
        namespace_roots: tuple[str, ...] = ("review_runtime",),
    ) -> tuple[str, ...]:
        probe = self.root / f"guard-failure-probe-{time.monotonic_ns()}.py"
        probe.write_text(
            "import pathlib\n"
            "import sys\n"
            f"guard = pathlib.Path({str(guard)!r})\n"
            f"sys.argv = [str(guard), *{guard_arguments!r}]\n"
            f"namespace_roots = {namespace_roots!r}\n"
            "namespace = {\n"
            "    '__name__': '_named_lane_guard_probe',\n"
            "    '__file__': str(guard),\n"
            "}\n"
            "try:\n"
            "    exec(compile(guard.read_bytes(), str(guard), 'exec'), namespace)\n"
            "except SystemExit as error:\n"
            "    failure = str(error)\n"
            "else:\n"
            "    raise RuntimeError('guard unexpectedly loaded a failing runtime')\n"
            "remaining = sorted(name for name in sys.modules if any(\n"
            "    name == root or name.startswith(f'{root}.')\n"
            "    for root in namespace_roots\n"
            "))\n"
            "if remaining:\n"
            "    raise RuntimeError(f'partial runtime modules remained: {remaining}')\n"
            "print(failure)\n",
            encoding="utf-8",
        )
        return (
            str(pathlib.Path(sys.executable).resolve()),
            "-I",
            "-B",
            "-S",
            str(probe),
        )

    def test_entrypoint_does_not_write_import_bytecode(self) -> None:
        scripts, guard = self.copy_guard_bundle()

        subprocess.run(
            self.isolated_guard_command(guard, "--help"),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(list(scripts.rglob("__pycache__")), [])

    def test_unchecked_pyc_fixture_matches_unoptimized_guard_subprocess(self) -> None:
        source_path = self.root / "guard-source.py"
        source_path.write_text("value = 1\n", encoding="utf-8")
        marker = self.root / "unchecked-pyc.marker"
        optimized_flags = mock.Mock(wraps=sys.flags)
        optimized_flags.optimize = 1
        ambient_cache = self.root / "absent-ambient-cache" / "deep"
        self.assertFalse(ambient_cache.parent.exists())

        with (
            mock.patch.object(sys, "flags", optimized_flags),
            mock.patch.object(sys, "pycache_prefix", str(ambient_cache)),
        ):
            cache_path = self.install_unchecked_pyc(
                source_path,
                marker,
                label="optimized-parent",
            )
        with mock.patch.object(sys, "pycache_prefix", None):
            expected_path = pathlib.Path(
                importlib.util.cache_from_source(
                    str(source_path),
                    optimization="",
                )
            )

        self.assertEqual(cache_path, expected_path)
        self.assertNotIn(".opt-", cache_path.name)
        self.assertFalse(cache_path.is_relative_to(ambient_cache))
        self.assertFalse(ambient_cache.parent.exists())

    def test_entrypoint_ignores_ambient_python_launch_controls(self) -> None:
        _, guard = self.copy_guard_bundle()
        attacker = self.root / "attacker"
        attacker.mkdir()
        fake_python_marker = self.root / "fake-python.marker"
        sitecustomize_marker = self.root / "sitecustomize.marker"
        fake_python = attacker / "python3"
        fake_python.write_text(
            f"#!/bin/sh\nprintf fake > {str(fake_python_marker)!r}\nexit 97\n",
            encoding="utf-8",
        )
        fake_python.chmod(0o755)
        (attacker / "sitecustomize.py").write_text(
            "import pathlib\n"
            f"pathlib.Path({str(sitecustomize_marker)!r}).write_text('loaded')\n",
            encoding="utf-8",
        )
        env_executable = pathlib.Path("/usr/bin/env")
        self.assertTrue(env_executable.is_file())

        completed = subprocess.run(
            (
                str(env_executable),
                "-i",
                f"PATH={attacker}",
                f"PYTHONHOME={attacker}",
                f"PYTHONPATH={attacker}",
                *self.isolated_guard_command(guard, "--help"),
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("usage:", completed.stdout)
        self.assertFalse(fake_python_marker.exists())
        self.assertFalse(sitecustomize_marker.exists())

    def test_entrypoint_skips_global_site_hooks_with_no_site(self) -> None:
        _, guard = self.copy_guard_bundle()
        environment_root = self.root / "sitecustomize-environment"
        venv.EnvBuilder(with_pip=False).create(environment_root)
        interpreter = environment_root / (
            "Scripts/python.exe" if os.name == "nt" else "bin/python"
        )
        self.assertTrue(interpreter.is_file())

        purelib_probe = subprocess.run(
            (
                str(interpreter),
                "-I",
                "-B",
                "-c",
                "import sysconfig; print(sysconfig.get_path('purelib'))",
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(purelib_probe.returncode, 0, purelib_probe.stderr)
        site_packages = pathlib.Path(purelib_probe.stdout.strip())
        self.assertTrue(site_packages.is_dir())
        marker = self.root / "global-site-hook.marker"
        # Executable .pth lines remain a venv site hook across Python 3.13 patches.
        (site_packages / "codex-review-site-hook.pth").write_text(
            f"import pathlib; pathlib.Path({str(marker)!r}).write_text('loaded')\n",
            encoding="utf-8",
        )

        unsafe_guard = subprocess.run(
            (str(interpreter), "-I", "-B", str(guard), "--help"),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertNotEqual(unsafe_guard.returncode, 0)
        self.assertIn("invoked with -I -B -S", unsafe_guard.stderr)
        self.assertEqual(marker.read_text(encoding="utf-8"), "loaded")
        marker.unlink()

        guarded = subprocess.run(
            self.isolated_guard_command(
                guard,
                "--help",
                python_executable=interpreter,
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(guarded.returncode, 0, guarded.stderr)
        self.assertIn("usage:", guarded.stdout)
        self.assertFalse(marker.exists())

    def test_entrypoint_loads_only_bound_runtime_sources(self) -> None:
        scripts, guard = self.copy_guard_bundle()
        runtime = scripts / "review_runtime"
        argparse_marker = self.root / "argparse-shadow.marker"
        json_marker = self.root / "json-shadow.marker"
        pyc_marker = self.root / "common-pyc.marker"
        for module_name, marker in (
            ("argparse", argparse_marker),
            ("json", json_marker),
        ):
            (scripts / f"{module_name}.py").write_text(
                "import pathlib\n"
                f"pathlib.Path({str(marker)!r}).write_text('loaded')\n"
                f"raise RuntimeError('malicious {module_name} shadow executed')\n",
                encoding="utf-8",
            )

        for suffix in importlib.machinery.EXTENSION_SUFFIXES:
            (runtime / f"common{suffix}").write_bytes(b"not an extension module")

        self.install_unchecked_pyc(
            runtime / "common.py",
            pyc_marker,
            label="common",
        )

        expected_origins = {
            "review_runtime": str(runtime / "__init__.py"),
            "review_runtime.common": str(runtime / "common.py"),
            "review_runtime.claude_version_policy": str(
                runtime / "claude_version_policy.py"
            ),
            "review_runtime.review_workspace": str(runtime / "review_workspace.py"),
            "review_runtime.named_lane": str(runtime / "named_lane.py"),
        }
        expected_fd_exec = str(runtime / "fd_exec.py")
        body = (
            "import json\n"
            f"expected = {expected_origins!r}\n"
            f"expected_fd_exec = {expected_fd_exec!r}\n"
            f"forbidden_paths = {{{str(scripts)!r}, {str(runtime)!r}}}\n"
            "if forbidden_paths.intersection(sys.path):\n"
            "    raise RuntimeError('candidate control path leaked into sys.path')\n"
            "observed = {}\n"
            "for name, origin in expected.items():\n"
            "    module = sys.modules[name]\n"
            "    observed[name] = {\n"
            "        'file': module.__file__,\n"
            "        'origin': module.__spec__.origin,\n"
            "        'cached': module.__cached__,\n"
            "    }\n"
            "    if module.__file__ != origin or module.__spec__.origin != origin:\n"
            "        raise RuntimeError(f'unexpected bound origin for {name}')\n"
            "if list(sys.modules['review_runtime'].__path__):\n"
            "    raise RuntimeError('bound package search path must remain closed')\n"
            "loaded = sorted(name for name in sys.modules "
            "if name == 'review_runtime' or name.startswith('review_runtime.'))\n"
            "if loaded != sorted(expected):\n"
            "    raise RuntimeError(f'unexpected runtime closure: {loaded}')\n"
            "if sys.modules['review_runtime.common'].FD_EXEC_BYTES != "
            "pathlib.Path(expected_fd_exec).read_bytes():\n"
            "    raise RuntimeError('fd_exec bytes were not bound exactly')\n"
            "print(json.dumps(observed, sort_keys=True))\n"
        )
        completed = subprocess.run(
            self.guard_probe_command(guard, body),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        observed = json.loads(completed.stdout)
        self.assertEqual(
            {name: details["origin"] for name, details in observed.items()},
            expected_origins,
        )
        self.assertTrue(all(details["cached"] is None for details in observed.values()))
        self.assertFalse(argparse_marker.exists())
        self.assertFalse(json_marker.exists())
        self.assertFalse(pyc_marker.exists())

    def test_preflight_entrypoint_loads_only_bound_manifest_sources(self) -> None:
        scripts, guard = self.copy_guard_bundle()
        runtime = scripts / "review_runtime"
        wrapper_marker = self.root / "preflight-wrapper.marker"
        json_marker = self.root / "preflight-json-shadow.marker"
        ssl_marker = self.root / "preflight-ssl-shadow.marker"
        pyc_marker = self.root / "preflight-provenance-pyc.marker"
        (scripts / "named_claude_preflight").write_text(
            f"#!/bin/sh\nprintf loaded > {str(wrapper_marker)!r}\nexit 97\n",
            encoding="utf-8",
        )
        (scripts / "named_claude_preflight").chmod(0o755)
        for module_name, marker in (("json", json_marker), ("ssl", ssl_marker)):
            (scripts / f"{module_name}.py").write_text(
                "import pathlib\n"
                f"pathlib.Path({str(marker)!r}).write_text('loaded')\n"
                f"raise RuntimeError('malicious {module_name} shadow executed')\n",
                encoding="utf-8",
            )
        for suffix in importlib.machinery.EXTENSION_SUFFIXES:
            (runtime / f"claude_provenance{suffix}").write_bytes(
                b"not an extension module"
            )
        self.install_unchecked_pyc(
            runtime / "claude_provenance.py",
            pyc_marker,
            label="claude-provenance",
        )

        expected_origins = {
            "review_runtime": str(runtime / "__init__.py"),
            "review_runtime.common": str(runtime / "common.py"),
            "review_runtime.claude_version_policy": str(
                runtime / "claude_version_policy.py"
            ),
            "review_runtime.claude_capabilities": str(
                runtime / "claude_capabilities.py"
            ),
            "review_runtime.claude_refresh_lock": str(
                runtime / "claude_refresh_lock.py"
            ),
            "review_runtime.claude_linux": str(runtime / "claude_linux.py"),
            "review_runtime.claude_provenance": str(runtime / "claude_provenance.py"),
            "review_runtime.claude_stream_contract": str(
                runtime / "claude_stream_contract.py"
            ),
            "review_runtime.named_claude_preflight": str(
                runtime / "named_claude_preflight.py"
            ),
        }
        expected_key = str(runtime / "claude_code_release.asc")
        expected_fd_exec = str(runtime / "fd_exec.py")
        body = (
            "import json\n"
            f"expected = {expected_origins!r}\n"
            f"expected_key = {expected_key!r}\n"
            f"expected_fd_exec = {expected_fd_exec!r}\n"
            "observed = {}\n"
            "for name, origin in expected.items():\n"
            "    module = sys.modules[name]\n"
            "    observed[name] = module.__spec__.origin\n"
            "    if module.__file__ != origin or module.__spec__.origin != origin:\n"
            "        raise RuntimeError(f'unexpected bound origin for {name}')\n"
            "if list(sys.modules['review_runtime'].__path__):\n"
            "    raise RuntimeError('bound package search path must remain closed')\n"
            "loaded = sorted(name for name in sys.modules "
            "if name == 'review_runtime' or name.startswith('review_runtime.'))\n"
            "if loaded != sorted(expected):\n"
            "    raise RuntimeError(f'unexpected preflight closure: {loaded}')\n"
            "key = sys.modules['review_runtime.claude_provenance']."
            "CLAUDE_RELEASE_KEY_PATH\n"
            "if str(key) != expected_key:\n"
            "    raise RuntimeError(f'unexpected release key path: {key}')\n"
            "key_bytes = sys.modules['review_runtime.claude_provenance']."
            "CLAUDE_RELEASE_KEY_BYTES\n"
            "if key_bytes != pathlib.Path(expected_key).read_bytes():\n"
            "    raise RuntimeError('release key bytes were not bound exactly')\n"
            "if sys.modules['review_runtime.common'].FD_EXEC_BYTES != "
            "pathlib.Path(expected_fd_exec).read_bytes():\n"
            "    raise RuntimeError('fd_exec bytes were not bound exactly')\n"
            "if namespace['_MAIN_ARGV'] != ('--sentinel',):\n"
            '    raise RuntimeError(f"arguments not forwarded: '
            "{namespace['_MAIN_ARGV']!r}\")\n"
            "print(json.dumps(observed, sort_keys=True))\n"
        )
        ast.parse(body, feature_version=(3, 10))
        completed = subprocess.run(
            self.guard_probe_command(
                guard,
                body,
                guard_arguments=("preflight-claude", "--sentinel"),
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout), expected_origins)
        self.assertFalse(wrapper_marker.exists())
        self.assertFalse(json_marker.exists())
        self.assertFalse(ssl_marker.exists())
        self.assertFalse(pyc_marker.exists())

    def test_preflight_entrypoint_uses_bound_linux_runtime_modules(self) -> None:
        scripts, guard = self.copy_guard_bundle()
        runtime = scripts / "review_runtime"
        body = (
            "import pathlib\n"
            "import types\n"
            "package = sys.modules['review_runtime']\n"
            "linux = sys.modules['review_runtime.claude_linux']\n"
            "provenance = sys.modules['review_runtime.claude_provenance']\n"
            f"expected_linux = {str(runtime / 'claude_linux.py')!r}\n"
            "if package.claude_linux is not linux:\n"
            "    raise RuntimeError('package did not retain the bound Linux module')\n"
            "if linux.__spec__.origin != expected_linux:\n"
            "    raise RuntimeError(f'unexpected Linux origin: "
            "{linux.__spec__.origin}')\n"
            "host = object()\n"
            "closure = object()\n"
            "calls = []\n"
            "linux.detect_host = lambda: host\n"
            "def collect(actual_host, executable, **kwargs):\n"
            "    calls.append(('collect', actual_host, executable, kwargs))\n"
            "    return closure\n"
            "def revalidate(actual_closure):\n"
            "    calls.append(('revalidate', actual_closure))\n"
            "    return actual_closure\n"
            "linux.collect_host_runtime_closure = collect\n"
            "linux.revalidate_host_runtime_closure = revalidate\n"
            "provenance.sys = types.SimpleNamespace(platform='linux')\n"
            "executable = pathlib.Path('/bound/gpg')\n"
            "trusted = provenance._prepare_trusted_gpg_runtime(executable)\n"
            "if trusted.linux_closure is not closure:\n"
            "    raise RuntimeError('Linux closure was not returned')\n"
            "provenance._revalidate_trusted_gpg_runtime(trusted)\n"
            "if calls[0][0:3] != ('collect', host, executable):\n"
            "    raise RuntimeError(f'unexpected Linux collection call: {calls[0]}')\n"
            "if calls[1] != ('revalidate', closure):\n"
            "    raise RuntimeError(f'unexpected Linux revalidation call: {calls[1]}')\n"
            "print(linux.__spec__.origin)\n"
        )
        completed = subprocess.run(
            self.guard_probe_command(
                guard,
                body,
                guard_arguments=("preflight-claude",),
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), str(runtime / "claude_linux.py"))

    @unittest.skipUnless(os.name == "posix", "account home requires POSIX")
    def test_preflight_profile_derives_home_with_scrubbed_environment(self) -> None:
        import pwd

        _, guard = self.copy_guard_bundle()
        body = (
            "import json\n"
            "module = sys.modules['review_runtime.named_claude_preflight']\n"
            "observed = {}\n"
            "def capture(*, explicit_path, explicit_version, home):\n"
            "    observed['explicit_path'] = explicit_path\n"
            "    observed['explicit_version'] = explicit_version\n"
            "    observed['home'] = str(home)\n"
            "    return {\n"
            "        'classification': 'blocked',\n"
            "        'reason': 'compatible-version-unavailable',\n"
            "    }\n"
            "module.preflight = capture\n"
            "returncode = namespace['main'](())\n"
            "print(json.dumps({\n"
            "    'home': observed['home'],\n"
            "    'explicit_path': observed['explicit_path'],\n"
            "    'explicit_version': observed['explicit_version'],\n"
            "    'returncode': returncode,\n"
            "}, sort_keys=True))\n"
        )
        completed = subprocess.run(
            self.guard_probe_command(
                guard,
                body,
                guard_arguments=("preflight-claude",),
            ),
            check=False,
            env={"LANG": "C", "LC_ALL": "C", "PATH": TRUSTED_PATH},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        lines = completed.stdout.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(
            json.loads(lines[0]),
            {
                "classification": "blocked",
                "reason": "compatible-version-unavailable",
            },
        )
        observed = json.loads(lines[1])
        expected_home = pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(
            strict=True
        )
        self.assertEqual(observed["home"], str(expected_home))
        self.assertIsNone(observed["explicit_path"])
        self.assertIsNone(observed["explicit_version"])
        self.assertEqual(observed["returncode"], 1)

    def test_validator_entrypoint_loads_only_bound_manifest_sources(self) -> None:
        scripts, guard = self.copy_guard_bundle()
        runtime = scripts / "review_runtime"
        argparse_marker = self.root / "validator-argparse-shadow.marker"
        json_marker = self.root / "validator-json-shadow.marker"
        pyc_marker = self.root / "validator-pyc.marker"
        for module_name, marker in (
            ("argparse", argparse_marker),
            ("json", json_marker),
        ):
            (scripts / f"{module_name}.py").write_text(
                "import pathlib\n"
                f"pathlib.Path({str(marker)!r}).write_text('loaded')\n"
                f"raise RuntimeError('malicious {module_name} shadow executed')\n",
                encoding="utf-8",
            )
        for suffix in importlib.machinery.EXTENSION_SUFFIXES:
            (scripts / f"validate_claude_stream{suffix}").write_bytes(
                b"not an extension module"
            )
        self.install_unchecked_pyc(
            scripts / "validate_claude_stream.py",
            pyc_marker,
            label="validate-claude-stream",
        )

        expected_origin = str(scripts / "validate_claude_stream.py")
        expected_runtime_origins = {
            "review_runtime": str(runtime / "__init__.py"),
            "review_runtime.common": str(runtime / "common.py"),
            "review_runtime.claude_version_policy": str(
                runtime / "claude_version_policy.py"
            ),
            "review_runtime.claude_capabilities": str(
                runtime / "claude_capabilities.py"
            ),
            "review_runtime.claude_refresh_lock": str(
                runtime / "claude_refresh_lock.py"
            ),
            "review_runtime.claude_linux": str(runtime / "claude_linux.py"),
            "review_runtime.claude_provenance": str(runtime / "claude_provenance.py"),
            "review_runtime.claude_stream_contract": str(
                runtime / "claude_stream_contract.py"
            ),
        }
        expected_companions = {
            "COMPATIBILITY": str(
                scripts.parent / "references/claude-stream-compatibility.json"
            ),
            "BASELINE": str(
                scripts.parent / "references/claude-2.1.212-stream-schema.json"
            ),
            "PROFILE": str(scripts.parent / "references/claude-stream-schema.json"),
            "CAPABILITY": str(runtime / "claude_capabilities.py"),
        }
        body = (
            "module = sys.modules['validate_claude_stream']\n"
            f"expected_origin = {expected_origin!r}\n"
            f"expected_runtime = {expected_runtime_origins!r}\n"
            f"expected_companions = {expected_companions!r}\n"
            "if module.__file__ != expected_origin:\n"
            "    raise RuntimeError(f'unexpected validator file: {module.__file__}')\n"
            "if module.__spec__.origin != expected_origin:\n"
            "    raise RuntimeError(f'unexpected validator origin: "
            "{module.__spec__.origin}')\n"
            "if module.__package__ != '':\n"
            "    raise RuntimeError(f'unexpected validator package: "
            "{module.__package__!r}')\n"
            "for name, origin in expected_runtime.items():\n"
            "    runtime_module = sys.modules[name]\n"
            "    if runtime_module.__file__ != origin "
            "or runtime_module.__spec__.origin != origin:\n"
            "        raise RuntimeError(f'unexpected runtime origin for {name}')\n"
            "if list(sys.modules['review_runtime'].__path__):\n"
            "    raise RuntimeError('bound package search path must remain closed')\n"
            "if sys.modules['review_runtime.common'].FD_EXEC_BYTES is not None:\n"
            "    raise RuntimeError('validator unexpectedly bound process companion')\n"
            "path_and_bytes = (\n"
            "    ('COMPATIBILITY_PATH', 'COMPATIBILITY_JSON_BYTES', "
            "expected_companions['COMPATIBILITY']),\n"
            "    ('SCHEMA_PATH', 'PROFILE_SCHEMA_BYTES', "
            "expected_companions['PROFILE']),\n"
            "    ('CAPABILITY_PATH', 'CAPABILITY_SOURCE_BYTES', "
            "expected_companions['CAPABILITY']),\n"
            ")\n"
            "for path_name, bytes_name, expected_path in path_and_bytes:\n"
            "    if str(getattr(module, path_name)) != expected_path:\n"
            "        raise RuntimeError(f'unexpected companion path: {path_name}')\n"
            "    if getattr(module, bytes_name) != pathlib.Path(expected_path).read_bytes():\n"
            "        raise RuntimeError(f'companion bytes were not bound: {bytes_name}')\n"
            "if module.BASELINE_SCHEMA_BYTES != pathlib.Path("
            "expected_companions['BASELINE']).read_bytes():\n"
            "    raise RuntimeError('baseline companion bytes were not bound')\n"
            "loaded = sorted(name for name in sys.modules "
            "if name == 'review_runtime' or name.startswith('review_runtime.') "
            "or name == 'validate_claude_stream' "
            "or name.startswith('validate_claude_stream.'))\n"
            "expected_loaded = sorted([*expected_runtime, 'validate_claude_stream'])\n"
            "if loaded != expected_loaded:\n"
            "    raise RuntimeError(f'unexpected validator closure: {loaded}')\n"
            "if namespace['_MAIN_ARGV'] != ('--sentinel',):\n"
            '    raise RuntimeError(f"arguments not forwarded: '
            "{namespace['_MAIN_ARGV']!r}\")\n"
            "print(module.__spec__.origin)\n"
        )
        ast.parse(body, feature_version=(3, 10))
        completed = subprocess.run(
            self.guard_probe_command(
                guard,
                body,
                guard_arguments=("validate-claude-stream", "--sentinel"),
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), expected_origin)
        self.assertFalse(argparse_marker.exists())
        self.assertFalse(json_marker.exists())
        self.assertFalse(pyc_marker.exists())

    def test_review_result_entrypoint_loads_only_bound_manifest_sources(
        self,
    ) -> None:
        scripts, guard = self.copy_guard_bundle()
        runtime = scripts / "review_runtime"
        argparse_marker = self.root / "review-result-argparse-shadow.marker"
        json_marker = self.root / "review-result-json-shadow.marker"
        pyc_marker = self.root / "review-result-pyc.marker"
        for module_name, marker in (
            ("argparse", argparse_marker),
            ("json", json_marker),
        ):
            (scripts / f"{module_name}.py").write_text(
                "import pathlib\n"
                f"pathlib.Path({str(marker)!r}).write_text('loaded')\n"
                f"raise RuntimeError('malicious {module_name} shadow executed')\n",
                encoding="utf-8",
            )
        for suffix in importlib.machinery.EXTENSION_SUFFIXES:
            (runtime / f"review_result{suffix}").write_bytes(b"not an extension module")
        self.install_unchecked_pyc(
            runtime / "review_result.py",
            pyc_marker,
            label="review-result",
        )

        expected_origins = {
            "review_runtime": str(runtime / "__init__.py"),
            "review_runtime.review_result": str(runtime / "review_result.py"),
        }
        body = (
            f"expected = {expected_origins!r}\n"
            "for name, origin in expected.items():\n"
            "    module = sys.modules[name]\n"
            "    if module.__file__ != origin or module.__spec__.origin != origin:\n"
            "        raise RuntimeError(f'unexpected review-result origin for {name}')\n"
            "    if module.__cached__ is not None:\n"
            "        raise RuntimeError(f'unexpected review-result cache for {name}')\n"
            "if list(sys.modules['review_runtime'].__path__):\n"
            "    raise RuntimeError('bound package search path must remain closed')\n"
            "loaded = sorted(name for name in sys.modules "
            "if name == 'review_runtime' or name.startswith('review_runtime.'))\n"
            "if loaded != sorted(expected):\n"
            "    raise RuntimeError(f'unexpected review-result closure: {loaded}')\n"
            "print(sys.modules['review_runtime.review_result'].__spec__.origin)\n"
        )
        completed = subprocess.run(
            self.guard_probe_command(
                guard,
                body,
                guard_arguments=("classify-review-result", "--sentinel"),
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            completed.stdout.strip(),
            expected_origins["review_runtime.review_result"],
        )
        raw_result = b"Reviewed the changed paths.\r\nNo findings.\r\n"
        classified = subprocess.run(
            self.isolated_guard_command(
                guard,
                "classify-review-result",
                "--content-assessment",
                "summary-only",
            ),
            check=False,
            input=raw_result,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(classified.returncode, 0, classified.stderr.decode())
        disposition = json.loads(classified.stdout)
        self.assertEqual(disposition["raw_result"], raw_result.decode("utf-8"))
        self.assertEqual(disposition["review_outcome"], "clean")
        self.assertEqual(disposition["presentation"], "extended-clean")
        self.assertFalse(argparse_marker.exists())
        self.assertFalse(json_marker.exists())
        self.assertFalse(pyc_marker.exists())

    def test_review_result_source_content_is_revalidated_before_main(self) -> None:
        scripts, guard = self.copy_guard_bundle()
        review_result = scripts / "review_runtime/review_result.py"
        body = (
            "import os\n"
            f"review_result = pathlib.Path({str(review_result)!r})\n"
            "before = os.stat(review_result, follow_symlinks=False)\n"
            "with review_result.open('r+b') as stream:\n"
            "    original = stream.read(1)\n"
            "    stream.seek(0)\n"
            "    stream.write(b'X' if original != b'X' else b'Y')\n"
            "    stream.flush()\n"
            "    os.fsync(stream.fileno())\n"
            "after = os.stat(review_result, follow_symlinks=False)\n"
            "identity = lambda value: (value.st_dev, value.st_ino, "
            "value.st_mode, value.st_uid, value.st_size)\n"
            "if identity(before) != identity(after):\n"
            "    raise RuntimeError('fixture did not preserve source identity')\n"
            "try:\n"
            "    namespace['main'](('--content-assessment', 'summary-only'))\n"
            "except SystemExit as error:\n"
            "    failure = str(error)\n"
            "else:\n"
            "    raise RuntimeError('guard accepted review-result source drift')\n"
            "if 'companion content changed' not in failure:\n"
            "    raise RuntimeError(f'unexpected guard failure: {failure}')\n"
            "print(failure)\n"
        )
        completed = subprocess.run(
            self.guard_probe_command(
                guard,
                body,
                guard_arguments=("classify-review-result",),
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("companion content changed", completed.stdout)

    def test_review_result_source_same_content_replacement_is_allowed(self) -> None:
        scripts, guard = self.copy_guard_bundle()
        review_result = scripts / "review_runtime/review_result.py"
        replacement = review_result.with_name("replacement-review_result.py")
        body = (
            "import os\n"
            f"review_result = pathlib.Path({str(review_result)!r})\n"
            f"replacement = pathlib.Path({str(replacement)!r})\n"
            "replacement.write_bytes(review_result.read_bytes())\n"
            "os.replace(replacement, review_result)\n"
            "try:\n"
            "    namespace['main'](('--help',))\n"
            "except SystemExit as error:\n"
            "    if error.code != 0:\n"
            "        raise\n"
            "else:\n"
            "    raise RuntimeError('help did not exit')\n"
            "print('same-content replacement accepted')\n"
        )
        completed = subprocess.run(
            self.guard_probe_command(
                guard,
                body,
                guard_arguments=("classify-review-result",),
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            completed.stdout.splitlines()[-1],
            "same-content replacement accepted",
        )

    def test_control_companions_must_be_ordinary_non_symlink_files(self) -> None:
        cases = (
            (
                "preflight-claude",
                lambda scripts: scripts / "review_runtime/claude_code_release.asc",
            ),
            (
                "validate-claude-stream",
                lambda scripts: self.stream_companion_paths(scripts)[0],
            ),
            (
                "validate-claude-stream",
                lambda scripts: self.stream_companion_paths(scripts)[1],
            ),
            (
                "validate-claude-stream",
                lambda scripts: self.stream_companion_paths(scripts)[2],
            ),
            (
                "validate-claude-stream",
                lambda scripts: self.stream_companion_paths(scripts)[3],
            ),
            (
                "preflight-claude",
                lambda scripts: scripts / "review_runtime/fd_exec.py",
            ),
            (
                "classify-review-result",
                lambda scripts: scripts / "review_runtime/review_result.py",
            ),
        )
        for subcommand, companion_path in cases:
            for replacement_type in ("symlink", "directory"):
                with self.subTest(
                    subcommand=subcommand,
                    replacement_type=replacement_type,
                ):
                    scripts, guard = self.copy_guard_bundle()
                    companion = companion_path(scripts)
                    payload = companion.read_bytes()
                    companion.unlink()
                    if replacement_type == "symlink":
                        target = self.root / f"companion-{time.monotonic_ns()}"
                        target.write_bytes(payload)
                        companion.symlink_to(target)
                    else:
                        companion.mkdir()

                    completed = subprocess.run(
                        self.isolated_guard_command(guard, subcommand),
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )

                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn(
                        f"{companion.name} must be an ordinary non-symlink regular file",
                        completed.stderr,
                    )

    def test_control_companion_same_content_replacement_is_allowed(self) -> None:
        for companion_index in range(4):
            with self.subTest(companion_index=companion_index):
                scripts, guard = self.copy_guard_bundle()
                companion = self.stream_companion_paths(scripts)[companion_index]
                replacement = companion.with_name(
                    f"replacement-{companion_index}-{companion.name}"
                )
                body = (
                    "import os\n"
                    f"companion = pathlib.Path({str(companion)!r})\n"
                    f"replacement = pathlib.Path({str(replacement)!r})\n"
                    "replacement.write_bytes(companion.read_bytes())\n"
                    "os.replace(replacement, companion)\n"
                    "result = namespace['main'](('--help',))\n"
                    "if result != 3:\n"
                    "    raise RuntimeError(f'unexpected validator result: {result}')\n"
                    "print('same-content replacement accepted')\n"
                )
                completed = subprocess.run(
                    self.guard_probe_command(
                        guard,
                        body,
                        guard_arguments=("validate-claude-stream",),
                    ),
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(
                    completed.stdout.splitlines()[-1],
                    "same-content replacement accepted",
                )

    def test_control_companion_content_is_revalidated_before_main(self) -> None:
        for companion_index in range(4):
            with self.subTest(companion_index=companion_index):
                scripts, guard = self.copy_guard_bundle()
                companion = self.stream_companion_paths(scripts)[companion_index]
                body = (
                    "import os\n"
                    f"companion = pathlib.Path({str(companion)!r})\n"
                    "before = os.stat(companion, follow_symlinks=False)\n"
                    "with companion.open('r+b') as stream:\n"
                    "    original = stream.read(1)\n"
                    "    stream.seek(0)\n"
                    "    stream.write(b'X' if original != b'X' else b'Y')\n"
                    "    stream.flush()\n"
                    "    os.fsync(stream.fileno())\n"
                    "after = os.stat(companion, follow_symlinks=False)\n"
                    "identity = lambda value: (value.st_dev, value.st_ino, "
                    "value.st_mode, value.st_uid, value.st_size)\n"
                    "if identity(before) != identity(after):\n"
                    "    raise RuntimeError('fixture did not preserve companion identity')\n"
                    "try:\n"
                    "    namespace['main'](())\n"
                    "except SystemExit as error:\n"
                    "    failure = str(error)\n"
                    "else:\n"
                    "    raise RuntimeError('guard accepted companion content drift')\n"
                    "if 'companion content changed' not in failure:\n"
                    "    raise RuntimeError(f'unexpected guard failure: {failure}')\n"
                    "print(failure)\n"
                )
                completed = subprocess.run(
                    self.guard_probe_command(
                        guard,
                        body,
                        guard_arguments=("validate-claude-stream",),
                    ),
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("companion content changed", completed.stdout)

    @unittest.skipUnless(os.name == "posix", "descriptor launch requires POSIX")
    def test_fd_exec_replacement_after_final_revalidation_uses_bound_bytes(
        self,
    ) -> None:
        scripts, guard = self.copy_guard_bundle()
        fd_exec = scripts / "review_runtime/fd_exec.py"
        malicious = self.root / "malicious-fd-exec.py"
        marker = self.root / "malicious-fd-exec.marker"
        review_cwd = self.root / "bound-fd-exec-cwd"
        review_cwd.mkdir()
        malicious.write_text(
            f"import pathlib\npathlib.Path({str(marker)!r}).write_text('reopened')\n",
            encoding="utf-8",
        )
        body = (
            "import os\n"
            f"fd_exec = pathlib.Path({str(fd_exec)!r})\n"
            f"malicious = pathlib.Path({str(malicious)!r})\n"
            f"marker = pathlib.Path({str(marker)!r})\n"
            f"review_cwd = pathlib.Path({str(review_cwd)!r})\n"
            "common = sys.modules['review_runtime.common']\n"
            "if common.FD_EXEC_BYTES != fd_exec.read_bytes():\n"
            "    raise RuntimeError('formal common did not retain fd_exec bytes')\n"
            "original_validate = namespace['_validate_bound_companion']\n"
            "initial_binding = original_validate(fd_exec)\n"
            "def validate_then_replace(path):\n"
            "    binding = original_validate(path)\n"
            "    path.unlink()\n"
            "    path.symlink_to(malicious)\n"
            "    return binding\n"
            "namespace['_validate_bound_companion'] = validate_then_replace\n"
            "def consume(_argv):\n"
            "    directory_fd = os.open(review_cwd, os.O_RDONLY)\n"
            "    try:\n"
            "        return common.run(\n"
            "            (sys.executable, '-c', "
            "'import os; os.write(1, os.getcwd().encode())'),\n"
            "            cwd_fd=directory_fd,\n"
            "        )\n"
            "    finally:\n"
            "        os.close(directory_fd)\n"
            "guarded = namespace['_guard_companions'](\n"
            "    consume, ((fd_exec, initial_binding),)\n"
            ")\n"
            "completed = guarded(())\n"
            "if completed.returncode != 0:\n"
            "    raise RuntimeError(f'bound fd_exec failed: {completed.stderr!r}')\n"
            "if completed.stdout != os.fsencode(review_cwd):\n"
            "    raise RuntimeError(f'bound fd_exec used wrong cwd: "
            "{completed.stdout!r}')\n"
            "if marker.exists():\n"
            "    raise RuntimeError('formal common reopened the fd_exec path')\n"
            "if not fd_exec.is_symlink():\n"
            "    raise RuntimeError('fixture did not replace fd_exec with a symlink')\n"
            "print('bound fd_exec bytes executed')\n"
        )
        completed = subprocess.run(
            self.guard_probe_command(guard, body),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "bound fd_exec bytes executed")
        self.assertFalse(marker.exists())

    def test_control_consumer_uses_bound_bytes_after_final_revalidation(self) -> None:
        scripts, guard = self.copy_guard_bundle()
        companions = self.stream_companion_paths(scripts)
        replacements = tuple(
            companion.with_name(f"post-validation-{index}-{companion.name}")
            for index, companion in enumerate(companions)
        )
        body = (
            "import os\n"
            f"companions = tuple(pathlib.Path(path) for path in {tuple(map(str, companions))!r})\n"
            f"replacements = tuple(pathlib.Path(path) for path in {tuple(map(str, replacements))!r})\n"
            "module = sys.modules['validate_claude_stream']\n"
            "original_validate = namespace['_validate_bound_companion']\n"
            "initial_bindings = tuple(\n"
            "    (path, original_validate(path)) for path in companions\n"
            ")\n"
            "replacement_by_path = dict(zip(companions, replacements))\n"
            "for replacement in replacements:\n"
            "    replacement.write_bytes(b'not valid companion bytes')\n"
            "def validate_then_replace(path):\n"
            "    binding = original_validate(path)\n"
            "    os.replace(replacement_by_path[path], path)\n"
            "    return binding\n"
            "namespace['_validate_bound_companion'] = validate_then_replace\n"
            "def consume(_argv):\n"
            "    contract, binding = module._load_contract_with_binding()\n"
            "    return contract['claude_code_version'], binding\n"
            "guarded = namespace['_guard_companions'](\n"
            "    consume, initial_bindings\n"
            ")\n"
            "version, binding = guarded(())\n"
            "if version != {\n"
            "    'rule': 'strict_release_semver_range',\n"
            "    'minimum_inclusive': '2.1.211',\n"
            "    'maximum_exclusive': '3.0.0',\n"
            "}:\n"
            "    raise RuntimeError(f'unexpected bound schema version: {version}')\n"
            "if any(path.read_bytes() != b'not valid companion bytes' "
            "for path in companions):\n"
            "    raise RuntimeError('fixture did not replace every companion path')\n"
            "if binding.compatibility_digest != __import__('hashlib').sha256(\n"
            "    module.COMPATIBILITY_JSON_BYTES\n"
            ").hexdigest():\n"
            "    raise RuntimeError('validator did not consume bound compatibility bytes')\n"
            "if binding.baseline_digest != __import__('hashlib').sha256(\n"
            "    module.BASELINE_SCHEMA_BYTES\n"
            ").hexdigest():\n"
            "    raise RuntimeError('validator did not consume bound baseline bytes')\n"
            "if binding.capability_digest != __import__('hashlib').sha256(\n"
            "    module.CAPABILITY_SOURCE_BYTES\n"
            ").hexdigest():\n"
            "    raise RuntimeError('validator did not consume bound capability bytes')\n"
            "if binding.digest != __import__('hashlib').sha256(\n"
            "    module.COMPATIBILITY_JSON_BYTES + b'\\0'\n"
            "    + module.BASELINE_SCHEMA_BYTES + b'\\0'\n"
            "    + module.PROFILE_SCHEMA_BYTES + b'\\0'\n"
            "    + module.CAPABILITY_SOURCE_BYTES\n"
            ").hexdigest():\n"
            "    raise RuntimeError('validator did not consume every bound companion byte')\n"
            "print('bound stream profile')\n"
        )
        completed = subprocess.run(
            self.guard_probe_command(
                guard,
                body,
                guard_arguments=("validate-claude-stream",),
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "bound stream profile")

    def test_optional_control_load_failures_roll_back_their_namespaces(self) -> None:
        cases = (
            (
                "preflight-claude",
                ("review_runtime",),
                lambda scripts: scripts / "review_runtime/named_claude_preflight.py",
            ),
            (
                "validate-claude-stream",
                ("review_runtime", "validate_claude_stream"),
                lambda scripts: scripts / "validate_claude_stream.py",
            ),
        )
        for subcommand, namespace_roots, source_path in cases:
            with self.subTest(subcommand=subcommand):
                scripts, guard = self.copy_guard_bundle()
                source = source_path(scripts)
                source.write_text(
                    source.read_text(encoding="utf-8")
                    + "\nraise RuntimeError('synthetic optional loader failure')\n",
                    encoding="utf-8",
                )

                completed = subprocess.run(
                    self.guard_failure_probe_command(
                        guard,
                        guard_arguments=(subcommand,),
                        namespace_roots=namespace_roots,
                    ),
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("runtime execution failed", completed.stdout)

    def test_validator_subcommand_forwards_only_following_arguments(self) -> None:
        _, guard = self.copy_guard_bundle()
        missing_input = self.root / "missing-stream.jsonl"
        completed = subprocess.run(
            self.isolated_guard_command(
                guard,
                "validate-claude-stream",
                "--cwd",
                str(self.repo.resolve()),
                "--model",
                "claude-opus-4-8",
                "--preflight-result",
                str(self.root / "missing-preflight.json"),
                "--authentication-source",
                "local-login",
                "--process-returncode",
                "0",
                "--input",
                str(missing_input),
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.returncode, 3, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["classification"], "inconclusive")
        self.assertIn("validator.preflight-evidence-invalid", result["reasons"])

    def test_entrypoint_rejects_unbound_runtime_file_types(self) -> None:
        for replacement_type in ("symlink", "directory"):
            with self.subTest(replacement_type=replacement_type):
                scripts, guard = self.copy_guard_bundle()
                common = scripts / "review_runtime/common.py"
                common_payload = common.read_bytes()
                common.unlink()
                if replacement_type == "symlink":
                    target = self.root / f"common-target-{time.monotonic_ns()}.py"
                    target.write_bytes(common_payload)
                    common.symlink_to(target)
                else:
                    common.mkdir()

                completed = subprocess.run(
                    self.isolated_guard_command(guard, "--help"),
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(
                    "common.py must be an ordinary non-symlink regular file",
                    completed.stderr,
                )

    def test_entrypoint_fails_closed_when_bound_source_cannot_be_read(self) -> None:
        scripts, guard = self.copy_guard_bundle()
        common = scripts / "review_runtime/common.py"
        probe = self.root / "guard-read-failure-probe.py"
        probe.write_text(
            "import os\n"
            "import pathlib\n"
            "import sys\n"
            f"guard = pathlib.Path({str(guard)!r})\n"
            f"blocked = {common.name!r}\n"
            "real_open = os.open\n"
            "def guarded_open(path, flags, *args, **kwargs):\n"
            "    if os.fspath(path) == blocked:\n"
            "        raise PermissionError('synthetic source read denial')\n"
            "    return real_open(path, flags, *args, **kwargs)\n"
            "os.open = guarded_open\n"
            "namespace = {\n"
            "    '__name__': '_named_lane_guard_probe',\n"
            "    '__file__': str(guard),\n"
            "}\n"
            "try:\n"
            "    exec(compile(guard.read_bytes(), str(guard), 'exec'), namespace)\n"
            "except SystemExit as error:\n"
            "    failure = str(error)\n"
            "else:\n"
            "    raise RuntimeError('guard unexpectedly accepted an unreadable source')\n"
            "finally:\n"
            "    os.open = real_open\n"
            "if 'cannot read common.py' not in failure:\n"
            "    raise RuntimeError(f'unexpected guard failure: {failure}')\n"
            "print(failure)\n",
            encoding="utf-8",
        )
        completed = subprocess.run(
            (
                str(pathlib.Path(sys.executable).resolve()),
                "-I",
                "-B",
                "-S",
                str(probe),
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("cannot read common.py", completed.stdout)

    @unittest.skipUnless(
        hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
        "requires POSIX FIFO support",
    )
    def test_entrypoint_bound_source_fifo_swap_fails_without_blocking(self) -> None:
        scripts, guard = self.copy_guard_bundle()
        common = scripts / "review_runtime/common.py"
        probe = self.root / "guard-fifo-swap-probe.py"
        probe.write_text(
            "import os\n"
            "import pathlib\n"
            f"guard = pathlib.Path({str(guard)!r})\n"
            f"common = pathlib.Path({str(common)!r})\n"
            f"blocked = {common.name!r}\n"
            "real_open = os.open\n"
            "requested_flags = []\n"
            "swapped = False\n"
            "def guarded_open(path, flags, *args, **kwargs):\n"
            "    global swapped\n"
            "    if os.fspath(path) == blocked and not swapped:\n"
            "        swapped = True\n"
            "        common.unlink()\n"
            "        os.mkfifo(common, mode=0o600)\n"
            "        requested_flags.append(flags)\n"
            "        flags |= os.O_NONBLOCK\n"
            "    return real_open(path, flags, *args, **kwargs)\n"
            "os.open = guarded_open\n"
            "namespace = {\n"
            "    '__name__': '_named_lane_guard_probe',\n"
            "    '__file__': str(guard),\n"
            "}\n"
            "try:\n"
            "    exec(compile(guard.read_bytes(), str(guard), 'exec'), namespace)\n"
            "except SystemExit as error:\n"
            "    failure = str(error)\n"
            "else:\n"
            "    raise RuntimeError('guard unexpectedly accepted a FIFO source')\n"
            "finally:\n"
            "    os.open = real_open\n"
            "if not swapped or len(requested_flags) != 1:\n"
            "    raise RuntimeError('fixture did not swap the bound source')\n"
            "if not requested_flags[0] & os.O_NONBLOCK:\n"
            "    raise RuntimeError('bound source open omitted O_NONBLOCK')\n"
            "if 'common.py changed to a non-regular file' not in failure:\n"
            "    raise RuntimeError(f'unexpected guard failure: {failure}')\n"
            "print(failure)\n",
            encoding="utf-8",
        )
        completed = subprocess.run(
            (
                str(pathlib.Path(sys.executable).resolve()),
                "-I",
                "-B",
                "-S",
                str(probe),
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("common.py changed to a non-regular file", completed.stdout)

    def test_entrypoint_rolls_back_partial_bound_runtime_modules(self) -> None:
        scripts, guard = self.copy_guard_bundle()
        named_lane = scripts / "review_runtime/named_lane.py"
        named_lane.write_text(
            named_lane.read_text(encoding="utf-8")
            + "\nraise RuntimeError('synthetic runtime execution failure')\n",
            encoding="utf-8",
        )
        completed = subprocess.run(
            self.guard_failure_probe_command(guard),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("runtime execution failed", completed.stdout)

    def test_entrypoint_precompiles_all_sources_before_execution(self) -> None:
        scripts, guard = self.copy_guard_bundle()
        package_marker = self.root / "package-executed-before-compile.marker"
        package = scripts / "review_runtime/__init__.py"
        package.write_text(
            package.read_text(encoding="utf-8")
            + "\nimport pathlib\n"
            + f"pathlib.Path({str(package_marker)!r}).write_text('executed')\n",
            encoding="utf-8",
        )
        (scripts / "review_runtime/named_lane.py").write_text(
            "def invalid syntax\n",
            encoding="utf-8",
        )

        completed = subprocess.run(
            self.guard_failure_probe_command(guard),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("cannot compile named_lane.py", completed.stdout)
        self.assertFalse(package_marker.exists())

    def test_entrypoint_rolls_back_when_entrypoint_is_missing(self) -> None:
        scripts, guard = self.copy_guard_bundle()
        (scripts / "review_runtime/named_lane.py").write_text(
            "from __future__ import annotations\nfrom .common import ReviewError\n",
            encoding="utf-8",
        )

        completed = subprocess.run(
            self.guard_failure_probe_command(guard),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("runtime execution failed", completed.stdout)

    def test_entrypoint_rejects_preexisting_runtime_module_collisions(self) -> None:
        for collision in ("review_runtime", "review_runtime.attacker"):
            with self.subTest(collision=collision):
                _, guard = self.copy_guard_bundle()
                probe = self.root / f"guard-collision-{time.monotonic_ns()}.py"
                probe.write_text(
                    "import pathlib\n"
                    "import sys\n"
                    "import types\n"
                    f"guard = pathlib.Path({str(guard)!r})\n"
                    f"collision = {collision!r}\n"
                    "sentinel = types.ModuleType(collision)\n"
                    "sys.modules[collision] = sentinel\n"
                    "namespace = {\n"
                    "    '__name__': '_named_lane_guard_probe',\n"
                    "    '__file__': str(guard),\n"
                    "}\n"
                    "try:\n"
                    "    exec(compile(guard.read_bytes(), str(guard), 'exec'), namespace)\n"
                    "except SystemExit as error:\n"
                    "    failure = str(error)\n"
                    "else:\n"
                    "    raise RuntimeError('guard accepted a preexisting module')\n"
                    "if sys.modules.get(collision) is not sentinel:\n"
                    "    raise RuntimeError('guard replaced the preexisting module')\n"
                    "if 'already loaded' not in failure:\n"
                    "    raise RuntimeError(f'unexpected guard failure: {failure}')\n"
                    "print(failure)\n",
                    encoding="utf-8",
                )
                completed = subprocess.run(
                    (
                        str(pathlib.Path(sys.executable).resolve()),
                        "-I",
                        "-B",
                        "-S",
                        str(probe),
                    ),
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("already loaded", completed.stdout)

    def test_entrypoint_is_source_only_and_fails_closed_without_isolation(
        self,
    ) -> None:
        guard = SCRIPTS / "named_lane_guard"
        source = guard.read_text(encoding="utf-8")

        self.assertEqual(guard.stat().st_mode & 0o111, 0)
        self.assertFalse(source.startswith("#!"))
        completed = subprocess.run(
            (
                str(pathlib.Path(sys.executable).resolve()),
                "-E",
                "-s",
                "-B",
                str(guard),
                "--help",
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("invoked with -I -B -S", completed.stderr)

    def add_gitlink(self, path: str = "vendor") -> str:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        target = self.commit("gitlink target")
        git(
            self.repo,
            "update-index",
            "--add",
            "--cacheinfo",
            "160000",
            target,
            path,
        )
        git(self.repo, "commit", "-m", "add gitlink")
        return git(self.repo, "rev-parse", "HEAD")

    def add_deinitialized_gitlink(self, path: str = "vendor") -> str:
        source = self.root / "submodule-source"
        source.mkdir()
        git(source, "init", "-b", "master")
        git(source, "config", "user.name", "Named Lane Test")
        git(source, "config", "user.email", "named-lane@example.invalid")
        git(source, "config", "commit.gpgsign", "false")
        (source / "tracked.txt").write_text("submodule\n", encoding="utf-8")
        git(source, "add", "tracked.txt")
        git(source, "commit", "-m", "submodule fixture")
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit("superproject fixture")
        git(
            self.repo,
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            str(source),
            path,
        )
        git(self.repo, "commit", "-m", "add registered gitlink")
        git(self.repo, "submodule", "deinit", "-f", "--", path)
        return git(self.repo, "rev-parse", "HEAD")

    def legacy_prefix_history(self) -> tuple[str, str, str]:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("legacy base")
        (self.repo / "middle.txt").write_text("middle\n", encoding="utf-8")
        middle = self.commit("legacy middle")
        (self.repo / "head.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("legacy head")
        return base, middle, head

    def invoke_legacy_prefix_cli(
        self,
        *,
        source: pathlib.Path,
        temporary_path: pathlib.Path,
        head: str,
        prefixes: tuple[str, ...] = (),
        phase: str = "initial",
    ) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = named_lane_runtime.legacy_short_prefix_compatibility_main(
                source,
                temporary_path,
                head,
                phase,
                prefixes,
            )
        return returncode, stdout.getvalue(), stderr.getvalue()

    def test_legacy_short_prefix_receipts_emit_sorted_closed_schema_and_fixed_git_queries(
        self,
    ) -> None:
        base, middle, head = self.legacy_prefix_history()
        temporary_path = self.root / "legacy-prefix-view"
        supplied_prefixes = (middle[:10], base[:10])
        original_capture = named_lane_runtime.run_bounded_capture
        observed_queries: list[tuple[tuple[str, ...], dict[str, str]]] = []

        def record_queries(argv: object, **kwargs: object) -> object:
            command = tuple(argv)
            if f"--git-dir={temporary_path}" in command:
                observed_queries.append((command, dict(kwargs.get("env", {}))))
            return original_capture(command, **kwargs)

        with (
            mock.patch.dict(
                os.environ,
                {
                    "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(self.root / "ambient"),
                    "GIT_DIR": str(self.root / "ambient.git"),
                    "GIT_REPLACE_REF_BASE": "refs/replace-hostile/",
                },
                clear=False,
            ),
            mock.patch.object(
                named_lane_runtime,
                "run_bounded_capture",
                side_effect=record_queries,
            ),
        ):
            returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                source=self.repo.resolve(),
                temporary_path=temporary_path,
                head=head,
                prefixes=supplied_prefixes,
            )

        self.assertEqual(returncode, 0, stderr)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(
            set(payload),
            {
                "status",
                "schema_version",
                "phase",
                "head",
                "temporary_cleanup_status",
                "receipts",
            },
        )
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(
            payload["schema_version"],
            LEGACY_PREFIX_RECEIPT_SCHEMA_VERSION,
        )
        self.assertEqual(payload["phase"], "initial")
        self.assertEqual(payload["head"], head)
        self.assertEqual(payload["temporary_cleanup_status"], "complete")
        expected_prefixes = sorted(supplied_prefixes)
        self.assertEqual(
            [receipt["raw_prefix"] for receipt in payload["receipts"]],
            expected_prefixes,
        )
        resolved = {base[:10]: base, middle[:10]: middle}
        receipt_keys = {
            "raw_prefix",
            "head",
            "disambiguate_return_code",
            "disambiguated_object_ids",
            "commit_object_check_return_code",
            "object_type",
            "ancestry_return_code",
        }
        for receipt in payload["receipts"]:
            raw_prefix = receipt["raw_prefix"]
            self.assertEqual(set(receipt), receipt_keys)
            self.assertEqual(receipt["head"], head)
            self.assertEqual(receipt["disambiguate_return_code"], 0)
            self.assertEqual(
                receipt["disambiguated_object_ids"],
                [resolved[raw_prefix]],
            )
            self.assertEqual(receipt["commit_object_check_return_code"], 0)
            self.assertEqual(receipt["object_type"], "commit")
            self.assertEqual(receipt["ancestry_return_code"], 0)

        git_prefix = (
            str(named_lane_runtime.resolve_git()),
            "--no-pager",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.commitGraph=false",
            "-c",
            "core.multiPackIndex=false",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "diff.external=",
            f"--git-dir={temporary_path}",
        )
        expected_commands: list[tuple[str, ...]] = [
            (*git_prefix, "cat-file", "-t", head),
            (
                *git_prefix,
                "rev-list",
                "--objects",
                "--missing=error",
                "--quiet",
                head,
                "--",
            ),
        ]
        for raw_prefix in expected_prefixes:
            object_id = resolved[raw_prefix]
            expected_commands.extend(
                (
                    (*git_prefix, "rev-parse", f"--disambiguate={raw_prefix}"),
                    (*git_prefix, "cat-file", "-t", object_id),
                    (
                        *git_prefix,
                        "merge-base",
                        "--is-ancestor",
                        object_id,
                        head,
                    ),
                )
            )
        self.assertEqual(
            [command for command, _environment in observed_queries],
            expected_commands,
        )
        expected_environment = {
            "GIT_ASKPASS": "/usr/bin/false",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OBJECT_DIRECTORY": str(self.repo.resolve() / ".git" / "objects"),
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
            "PAGER": "cat",
            "PATH": TRUSTED_PATH,
            "SSH_ASKPASS": "/usr/bin/false",
        }
        for _command, environment in observed_queries:
            self.assertEqual(environment, expected_environment)
            self.assertNotIn("GIT_ALTERNATE_OBJECT_DIRECTORIES", environment)
            self.assertNotIn("GIT_DIR", environment)
            self.assertNotIn("GIT_REPLACE_REF_BASE", environment)
        self.assertFalse(temporary_path.exists())
        self.assertEqual(list(self.root.glob(".named-lane-materializer-*")), [])

    def test_legacy_short_prefix_receipts_allow_empty_complete_array(self) -> None:
        _base, _middle, head = self.legacy_prefix_history()
        temporary_path = self.root / "legacy-prefix-empty-view"

        returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
            source=self.repo.resolve(),
            temporary_path=temporary_path,
            head=head,
            prefixes=(),
            phase="final",
        )

        self.assertEqual(returncode, 0, stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["phase"], "final")
        self.assertEqual(payload["receipts"], [])
        self.assertEqual(payload["temporary_cleanup_status"], "complete")
        self.assertFalse(temporary_path.exists())

    def test_legacy_short_prefix_receipts_support_sha256_object_format(self) -> None:
        sha256_repo = self.root / "legacy-sha256-repo"
        sha256_repo.mkdir()
        git(sha256_repo, "init", "--object-format=sha256", "-b", "master")
        git(sha256_repo, "config", "user.name", "Named Lane Test")
        git(sha256_repo, "config", "user.email", "named-lane@example.invalid")
        git(sha256_repo, "config", "commit.gpgsign", "false")
        (sha256_repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        git(sha256_repo, "add", "AGENTS.md")
        git(sha256_repo, "commit", "-m", "sha256 legacy base")
        base = git(sha256_repo, "rev-parse", "HEAD")
        (sha256_repo / "head.txt").write_text("head\n", encoding="utf-8")
        git(sha256_repo, "add", "head.txt")
        git(sha256_repo, "commit", "-m", "sha256 legacy head")
        head = git(sha256_repo, "rev-parse", "HEAD")
        temporary_path = self.root / "legacy-sha256-view"

        returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
            source=sha256_repo.resolve(),
            temporary_path=temporary_path,
            head=head,
            prefixes=(base[:10],),
        )

        self.assertEqual(len(base), 64)
        self.assertEqual(len(head), 64)
        self.assertEqual(returncode, 0, stderr)
        self.assertEqual(stderr, "")
        receipt = json.loads(stdout)["receipts"][0]
        self.assertEqual(receipt["disambiguated_object_ids"], [base])
        self.assertEqual(receipt["object_type"], "commit")
        self.assertFalse(temporary_path.exists())

    def test_guard_help_omits_legacy_short_prefix_receipt_route(self) -> None:
        _scripts, guard = self.copy_guard_bundle()
        completed = subprocess.run(
            self.isolated_guard_command(guard, "--help"),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertNotIn("legacy-short-prefix-receipts", completed.stdout)

    def test_legacy_short_prefix_receipts_reject_current_head_prefix_without_receipts(
        self,
    ) -> None:
        _base, _middle, head = self.legacy_prefix_history()
        temporary_path = self.root / "legacy-current-prefix-view"
        original_capture = named_lane_runtime.run_bounded_capture
        observed_queries: list[tuple[str, ...]] = []

        def record_queries(argv: object, **kwargs: object) -> object:
            command = tuple(argv)
            if f"--git-dir={temporary_path}" in command:
                observed_queries.append(command)
            return original_capture(command, **kwargs)

        with mock.patch.object(
            named_lane_runtime,
            "run_bounded_capture",
            side_effect=record_queries,
        ):
            returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                source=self.repo.resolve(),
                temporary_path=temporary_path,
                head=head,
                prefixes=(head[:10],),
            )

        self.assertEqual(returncode, 75)
        self.assertEqual(stdout, "")
        self.assertEqual(
            json.loads(stderr),
            {
                "status": "inconclusive",
                "reason": "legacy-prefix-is-current-head",
            },
        )
        git_prefix = named_lane_runtime._legacy_prefix_git_prefix(
            named_lane_runtime.resolve_git(),
            temporary_path,
        )
        self.assertEqual(
            observed_queries,
            [
                (*git_prefix, "cat-file", "-t", head),
                (
                    *git_prefix,
                    "rev-list",
                    "--objects",
                    "--missing=error",
                    "--quiet",
                    head,
                    "--",
                ),
            ],
        )
        self.assertFalse(temporary_path.exists())

        missing_head = "0" * 40
        missing_head_path = self.root / "legacy-current-missing-head-view"
        returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
            source=self.repo.resolve(),
            temporary_path=missing_head_path,
            head=missing_head,
            prefixes=(missing_head[:10],),
        )
        self.assertEqual(returncode, 2)
        self.assertEqual(stdout, "")
        self.assertEqual(json.loads(stderr)["status"], "blocked-safety")
        self.assertFalse(missing_head_path.exists())

    def test_legacy_short_prefix_receipts_reject_missing_and_ambiguous_prefixes(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        missing_prefix = "0000000000"
        if head.startswith(missing_prefix):
            missing_prefix = "ffffffffff"
        temporary_path = self.root / "legacy-missing-prefix-view"

        returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
            source=self.repo.resolve(),
            temporary_path=temporary_path,
            head=head,
            prefixes=(missing_prefix,),
        )

        self.assertEqual(returncode, 75)
        self.assertEqual(stdout, "")
        self.assertEqual(
            json.loads(stderr),
            {"status": "inconclusive", "reason": "legacy-prefix-not-unique"},
        )
        with self.assertRaisesRegex(
            LegacyPrefixReceiptInconclusive,
            "legacy-prefix-not-unique",
        ):
            named_lane_runtime._parse_legacy_disambiguation(
                (
                    b"1234567890aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
                    b"1234567890bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
                ),
                "1234567890",
                40,
            )
        self.assertFalse(temporary_path.exists())

        overflow_path = self.root / "legacy-ambiguous-overflow-view"
        original_capture = named_lane_runtime.run_bounded_capture

        def overflow_disambiguation(argv: object, **kwargs: object) -> object:
            command = tuple(argv)
            if f"--git-dir={overflow_path}" in command and "rev-parse" in command:
                # The bounded capture exception does not identify whether
                # stdout or stderr overflowed. It therefore cannot prove
                # semantic ambiguity and must remain a safety failure.
                raise ReviewOutputLimitError("synthetic unclassified output overflow")
            return original_capture(command, **kwargs)

        with mock.patch.object(
            named_lane_runtime,
            "run_bounded_capture",
            side_effect=overflow_disambiguation,
        ):
            returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                source=self.repo.resolve(),
                temporary_path=overflow_path,
                head=head,
                prefixes=(base[:10],),
            )

        self.assertEqual(returncode, 2)
        self.assertEqual(stdout, "")
        self.assertEqual(
            json.loads(stderr),
            {"status": "blocked-safety", "reason": "output-limit"},
        )
        self.assertFalse(overflow_path.exists())

    def test_legacy_short_prefix_receipts_second_failure_has_no_partial_stdout(
        self,
    ) -> None:
        base, middle, head = self.legacy_prefix_history()
        ordered_prefixes = tuple(sorted((base[:10], middle[:10])))
        resolved = {base[:10]: base, middle[:10]: middle}
        first_prefix, failing_prefix = ordered_prefixes
        temporary_path = self.root / "legacy-second-prefix-failure-view"
        original_capture = named_lane_runtime._legacy_prefix_git_capture
        observed_receipt_queries: list[tuple[str, ...]] = []

        def fail_second_disambiguation(*args: object, **kwargs: object) -> object:
            arguments = tuple(args[8])
            if arguments[0] in {"rev-parse", "cat-file", "merge-base"}:
                observed_receipt_queries.append(arguments)
            if arguments == ("rev-parse", f"--disambiguate={failing_prefix}"):
                return 0, b""
            return original_capture(*args, **kwargs)

        with mock.patch.object(
            named_lane_runtime,
            "_legacy_prefix_git_capture",
            side_effect=fail_second_disambiguation,
        ):
            returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                source=self.repo.resolve(),
                temporary_path=temporary_path,
                head=head,
                prefixes=ordered_prefixes,
            )

        first_object = resolved[first_prefix]
        self.assertIn(
            ("merge-base", "--is-ancestor", first_object, head),
            observed_receipt_queries,
        )
        self.assertEqual(returncode, 75)
        self.assertEqual(stdout, "")
        self.assertEqual(
            json.loads(stderr),
            {"status": "inconclusive", "reason": "legacy-prefix-not-unique"},
        )
        self.assertFalse(temporary_path.exists())

    def test_legacy_short_prefix_receipts_reject_annotated_tag_exact_type(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        git(self.repo, "tag", "-a", "legacy-annotated", "-m", "legacy", base)
        tag_object = git(self.repo, "rev-parse", "refs/tags/legacy-annotated")
        temporary_path = self.root / "legacy-tag-prefix-view"

        returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
            source=self.repo.resolve(),
            temporary_path=temporary_path,
            head=head,
            prefixes=(tag_object[:10],),
        )

        self.assertEqual(returncode, 75)
        self.assertEqual(stdout, "")
        self.assertEqual(
            json.loads(stderr),
            {"status": "inconclusive", "reason": "legacy-prefix-not-commit"},
        )
        self.assertFalse(temporary_path.exists())

    def test_legacy_short_prefix_receipts_reject_nonancestor_commit(self) -> None:
        _base, _middle, head = self.legacy_prefix_history()
        tree = git(self.repo, "rev-parse", f"{head}^{{tree}}")
        nonancestor = git(self.repo, "commit-tree", tree, "-m", "nonancestor")
        temporary_path = self.root / "legacy-nonancestor-prefix-view"

        returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
            source=self.repo.resolve(),
            temporary_path=temporary_path,
            head=head,
            prefixes=(nonancestor[:10],),
        )

        self.assertEqual(returncode, 75)
        self.assertEqual(stdout, "")
        self.assertEqual(
            json.loads(stderr),
            {"status": "inconclusive", "reason": "legacy-prefix-not-ancestor"},
        )
        self.assertFalse(temporary_path.exists())

    def test_legacy_short_prefix_receipts_reject_incomplete_head_object_closure(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        blob = git(self.repo, "rev-parse", f"{head}:head.txt")
        blob_path = self.repo / ".git" / "objects" / blob[:2] / blob[2:]
        retained_blob = self.root / "temporarily-missing-head-blob"
        self.assertTrue(blob_path.is_file())
        blob_path.rename(retained_blob)
        temporary_path = self.root / "legacy-incomplete-head-view"

        try:
            returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                source=self.repo.resolve(),
                temporary_path=temporary_path,
                head=head,
                prefixes=(base[:10],),
            )
        finally:
            retained_blob.rename(blob_path)

        self.assertEqual(returncode, 2)
        self.assertEqual(stdout, "")
        payload = json.loads(stderr)
        self.assertEqual(payload["status"], "blocked-safety")
        self.assertEqual(payload["reason"], "legacy-prefix-git-process")
        self.assertFalse(temporary_path.exists())

    def test_legacy_short_prefix_receipts_ignore_source_grafts_and_replace_refs(
        self,
    ) -> None:
        base, middle, head = self.legacy_prefix_history()
        info = self.repo / ".git" / "info"
        info.mkdir(exist_ok=True)
        grafts = info / "grafts"
        grafts.write_text(f"{middle}\n", encoding="ascii")
        replace_ref = f"refs/replace/{base}"
        git(self.repo, "update-ref", replace_ref, middle)
        temporary_path = self.root / "legacy-source-metadata-isolation-view"

        try:
            returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                source=self.repo.resolve(),
                temporary_path=temporary_path,
                head=head,
                prefixes=(base[:10],),
            )
        finally:
            git(self.repo, "update-ref", "-d", replace_ref)
            grafts.unlink(missing_ok=True)

        self.assertEqual(returncode, 0, stderr)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(
            payload["receipts"][0]["disambiguated_object_ids"],
            [base],
        )
        self.assertEqual(payload["receipts"][0]["ancestry_return_code"], 0)
        self.assertFalse(temporary_path.exists())

    def test_legacy_short_prefix_receipts_reject_alternates_http_shallow_and_promisor_sources(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        objects = self.repo / ".git" / "objects"
        info = objects / "info"
        pack = objects / "pack"
        info.mkdir(exist_ok=True)
        pack.mkdir(exist_ok=True)
        config = self.repo / ".git" / "config"
        original_config = config.read_bytes()
        cases = (
            (info / "alternates", b"", "alternates"),
            (info / "http-alternates", b"", "HTTP alternates"),
            (self.repo / ".git" / "shallow", b"", "shallow"),
            (pack / "legacy.promisor", b"", "promisor state"),
            (pack / "legacy.BiTmAp", b"", "bitmap cache"),
        )

        for index, (state_path, content, expected_reason) in enumerate(cases):
            with self.subTest(state_path=state_path.name):
                state_path.write_bytes(content)
                temporary_path = self.root / f"legacy-hostile-source-{index}"
                try:
                    returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                        source=self.repo.resolve(),
                        temporary_path=temporary_path,
                        head=head,
                        prefixes=(base[:10],),
                    )
                finally:
                    state_path.unlink(missing_ok=True)
                self.assertEqual(returncode, 2)
                self.assertEqual(stdout, "")
                payload = json.loads(stderr)
                self.assertEqual(payload["status"], "blocked-safety")
                self.assertIn(expected_reason, payload["reason"])
                self.assertFalse(temporary_path.exists())

        config.write_bytes(original_config + b'[remote "origin"]\n\tpromisor = true\n')
        temporary_path = self.root / "legacy-promisor-config-source"
        try:
            returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                source=self.repo.resolve(),
                temporary_path=temporary_path,
                head=head,
                prefixes=(base[:10],),
            )
        finally:
            config.write_bytes(original_config)
        self.assertEqual(returncode, 2)
        self.assertEqual(stdout, "")
        payload = json.loads(stderr)
        self.assertEqual(payload["status"], "blocked-safety")
        self.assertIn("promisor configuration", payload["reason"])
        self.assertFalse(temporary_path.exists())

    def test_legacy_short_prefix_receipts_reject_linked_per_worktree_shallow_source(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        linked_source = self.root / "legacy-linked-source"
        git(self.repo, "worktree", "add", "--detach", str(linked_source), head)
        linked_admin = pathlib.Path(
            git(linked_source, "rev-parse", "--absolute-git-dir")
        )
        shallow = linked_admin / "shallow"
        shallow.write_bytes(b"")
        temporary_path = self.root / "legacy-linked-shallow-view"

        try:
            returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                source=linked_source.resolve(),
                temporary_path=temporary_path,
                head=head,
                prefixes=(base[:10],),
            )
        finally:
            shallow.unlink(missing_ok=True)

        self.assertEqual(returncode, 2)
        self.assertEqual(stdout, "")
        payload = json.loads(stderr)
        self.assertEqual(payload["status"], "blocked-safety")
        self.assertIn("per-worktree shallow", payload["reason"])
        self.assertFalse(temporary_path.exists())

    def test_legacy_short_prefix_receipts_reject_group_world_writable_source_policy(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        policy_paths = (
            self.repo,
            self.repo / ".git",
            self.repo / ".git" / "objects",
            self.repo / ".git" / "config",
        )

        for index, policy_path in enumerate(policy_paths):
            with self.subTest(policy_path=policy_path):
                original_mode = stat.S_IMODE(policy_path.lstat().st_mode)
                policy_path.chmod(original_mode | 0o022)
                temporary_path = self.root / f"legacy-unsafe-mode-view-{index}"
                try:
                    returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                        source=self.repo.resolve(),
                        temporary_path=temporary_path,
                        head=head,
                        prefixes=(base[:10],),
                    )
                finally:
                    policy_path.chmod(original_mode)

                self.assertEqual(returncode, 2)
                self.assertEqual(stdout, "")
                payload = json.loads(stderr)
                self.assertEqual(payload["status"], "blocked-safety")
                self.assertIn("group/world writable", payload["reason"])
                self.assertFalse(temporary_path.exists())

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL test")
    def test_legacy_short_prefix_receipts_reject_extended_acl_source_policy(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        objects = self.repo / ".git" / "objects"
        loose_object = objects / base[:2] / base[2:]
        username = pwd.getpwuid(os.geteuid()).pw_name
        for index, policy_path in enumerate((objects, loose_object)):
            with self.subTest(policy_path=policy_path):
                add_acl = subprocess.run(
                    [
                        "/bin/chmod",
                        "+a",
                        f"user:{username} allow write",
                        str(policy_path),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=5,
                )
                if add_acl.returncode != 0:
                    self.skipTest("filesystem does not support Darwin extended ACLs")
                listing = subprocess.run(
                    ["/bin/ls", "-lde", str(policy_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=5,
                )
                if listing.returncode != 0 or len(listing.stdout.splitlines()) < 2:
                    subprocess.run(
                        ["/bin/chmod", "-N", str(policy_path)],
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5,
                    )
                    self.skipTest("filesystem did not retain a Darwin extended ACL")

                temporary_path = self.root / f"legacy-extended-acl-source-view-{index}"
                try:
                    returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                        source=self.repo.resolve(),
                        temporary_path=temporary_path,
                        head=head,
                        prefixes=(base[:10],),
                    )
                finally:
                    subprocess.run(
                        ["/bin/chmod", "-N", str(policy_path)],
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5,
                    )

                self.assertEqual(returncode, 2)
                self.assertEqual(stdout, "")
                payload = json.loads(stderr)
                self.assertEqual(payload["status"], "blocked-safety")
                self.assertIn("extended ACL", payload["reason"])
                self.assertFalse(temporary_path.exists())

    def test_legacy_short_prefix_receipts_bound_object_store_policy_inventory(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        temporary_path = self.root / "legacy-object-policy-inventory-limit-view"

        with mock.patch.object(
            named_lane_runtime,
            "LEGACY_PREFIX_OBJECT_STORE_ENTRY_LIMIT",
            0,
        ):
            returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                source=self.repo.resolve(),
                temporary_path=temporary_path,
                head=head,
                prefixes=(base[:10],),
            )

        self.assertEqual(returncode, 2)
        self.assertEqual(stdout, "")
        payload = json.loads(stderr)
        self.assertEqual(payload["status"], "blocked-safety")
        self.assertIn("object-store entry limit", payload["reason"])
        self.assertFalse(temporary_path.exists())

    def test_legacy_object_store_policy_limit_precedes_next_inventory_entry(
        self,
    ) -> None:
        class Inventory:
            def __init__(self) -> None:
                self.calls = 0

            def __enter__(self) -> Inventory:
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def __iter__(self) -> Inventory:
                return self

            def __next__(self) -> object:
                self.calls += 1
                if self.calls == 1:
                    return mock.Mock(name="first")
                raise AssertionError("inventory was materialized beyond its limit")

        inventory = Inventory()
        storage = mock.Mock(objects=self.repo / ".git" / "objects")
        with (
            mock.patch.object(named_lane_runtime.os, "scandir", return_value=inventory),
            mock.patch.object(
                named_lane_runtime,
                "LEGACY_PREFIX_OBJECT_STORE_ENTRY_LIMIT",
                0,
            ),
            self.assertRaisesRegex(NamedLaneGuardError, "entry limit"),
        ):
            named_lane_runtime._verify_legacy_object_store_access_policy(
                storage,
                time.monotonic() + 10.0,
            )
        self.assertEqual(inventory.calls, 1)

    def test_legacy_object_store_policy_inventory_checks_global_deadline(
        self,
    ) -> None:
        objects = self.root / "legacy-deadline-objects"
        objects.mkdir(mode=0o700)
        for index in range(256):
            (objects / f"object-{index:03d}").write_bytes(b"object")
        storage = mock.Mock(objects=objects)
        checks = 0

        def check_deadline(_deadline: float, _label: str) -> float:
            nonlocal checks
            checks += 1
            if checks == 2:
                raise ReviewTimeoutError("inventory deadline expired")
            return 10.0

        with (
            mock.patch.object(
                named_lane_runtime,
                "_remaining_deadline_seconds",
                side_effect=check_deadline,
            ),
            self.assertRaisesRegex(ReviewTimeoutError, "deadline expired"),
        ):
            named_lane_runtime._verify_legacy_object_store_access_policy(
                storage,
                time.monotonic() + 10.0,
            )
        self.assertEqual(checks, 2)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL test")
    def test_legacy_short_prefix_receipts_reject_linked_common_parent_acl_grant(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        source_parent = self.root / "legacy-linked-source-parent"
        source_parent.mkdir(mode=0o700)
        linked_source = source_parent / "worktree"
        git(self.repo, "worktree", "add", "--detach", str(linked_source), head)
        username = pwd.getpwuid(os.geteuid()).pw_name
        add_acl = subprocess.run(
            [
                "/bin/chmod",
                "+a",
                f"user:{username} allow write,delete,delete_child",
                str(self.repo),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )
        if add_acl.returncode != 0:
            self.skipTest("filesystem does not support Darwin extended ACLs")
        temporary_parent = self.root / "legacy-linked-safe-temporary-parent"
        temporary_parent.mkdir(mode=0o700)
        temporary_path = temporary_parent / "view"

        try:
            returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                source=linked_source.resolve(),
                temporary_path=temporary_path,
                head=head,
                prefixes=(base[:10],),
            )
        finally:
            subprocess.run(
                ["/bin/chmod", "-N", str(self.repo)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )

        self.assertEqual(returncode, 2)
        self.assertEqual(stdout, "")
        payload = json.loads(stderr)
        self.assertEqual(payload["status"], "blocked-safety")
        self.assertIn("extended ACL grant", payload["reason"])
        self.assertFalse(temporary_path.exists())

    @unittest.skipUnless(sys.platform == "darwin", "Darwin sticky custody test")
    def test_legacy_short_prefix_receipts_accept_root_owned_sticky_source_ancestor(
        self,
    ) -> None:
        sticky_parent = pathlib.Path("/private/tmp")
        try:
            sticky_metadata = sticky_parent.lstat()
        except OSError:
            self.skipTest("root-owned sticky temporary directory is unavailable")
        if (
            not stat.S_ISDIR(sticky_metadata.st_mode)
            or sticky_metadata.st_uid != 0
            or not stat.S_IMODE(sticky_metadata.st_mode) & stat.S_ISVTX
        ):
            self.skipTest("root-owned sticky temporary directory is unavailable")

        base, _middle, head = self.legacy_prefix_history()
        linked_source = sticky_parent / f"{self.root.name}-legacy-sticky-source"
        if linked_source.exists():
            self.fail(f"unexpected sticky-source fixture collision: {linked_source}")
        git(self.repo, "worktree", "add", "--detach", str(linked_source), head)
        temporary_path = self.root / "legacy-sticky-source-view"
        try:
            returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                source=linked_source.resolve(),
                temporary_path=temporary_path,
                head=head,
                prefixes=(base[:10],),
            )
        finally:
            shutil.rmtree(linked_source, ignore_errors=True)

        self.assertEqual(returncode, 0, stderr)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(
            payload["receipts"][0]["disambiguated_object_ids"],
            [base],
        )
        self.assertFalse(temporary_path.exists())

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL test")
    def test_legacy_short_prefix_receipts_revalidate_extended_acl_after_query(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        objects = self.repo / ".git" / "objects"
        username = pwd.getpwuid(os.geteuid()).pw_name
        temporary_path = self.root / "legacy-extended-acl-drift-view"
        original_capture = named_lane_runtime.run_bounded_capture
        mutated = False

        def add_acl_after_query(argv: object, **kwargs: object) -> object:
            nonlocal mutated
            command = tuple(argv)
            result = original_capture(command, **kwargs)
            if (
                not mutated
                and f"--git-dir={temporary_path}" in command
                and "rev-parse" in command
            ):
                completed = subprocess.run(
                    [
                        "/bin/chmod",
                        "+a",
                        f"user:{username} allow write",
                        str(objects),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=5,
                )
                if completed.returncode != 0:
                    raise RuntimeError("Darwin extended ACL fixture is unavailable")
                mutated = True
            return result

        try:
            with mock.patch.object(
                named_lane_runtime,
                "run_bounded_capture",
                side_effect=add_acl_after_query,
            ):
                returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                    source=self.repo.resolve(),
                    temporary_path=temporary_path,
                    head=head,
                    prefixes=(base[:10],),
                )
        finally:
            subprocess.run(
                ["/bin/chmod", "-N", str(objects)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )

        if not mutated:
            self.skipTest("filesystem does not support Darwin extended ACLs")
        self.assertEqual(returncode, 2)
        self.assertEqual(stdout, "")
        payload = json.loads(stderr)
        self.assertEqual(payload["status"], "blocked-safety")
        self.assertIn("extended ACL", payload["reason"])
        self.assertFalse(temporary_path.exists())

    def test_legacy_short_prefix_receipts_revalidate_source_config_after_each_query(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        config = self.repo / ".git" / "config"
        original_config = config.read_bytes()
        temporary_path = self.root / "legacy-source-config-drift-view"
        original_capture = named_lane_runtime.run_bounded_capture
        mutated = False

        def mutate_source_config(argv: object, **kwargs: object) -> object:
            nonlocal mutated
            command = tuple(argv)
            result = original_capture(command, **kwargs)
            if (
                not mutated
                and f"--git-dir={temporary_path}" in command
                and "rev-parse" in command
            ):
                config.write_bytes(original_config + b"# hostile drift\n")
                mutated = True
            return result

        try:
            with mock.patch.object(
                named_lane_runtime,
                "run_bounded_capture",
                side_effect=mutate_source_config,
            ):
                returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                    source=self.repo.resolve(),
                    temporary_path=temporary_path,
                    head=head,
                    prefixes=(base[:10],),
                )
        finally:
            config.write_bytes(original_config)

        self.assertTrue(mutated)
        self.assertEqual(returncode, 2)
        self.assertEqual(stdout, "")
        payload = json.loads(stderr)
        self.assertEqual(payload["status"], "blocked-safety")
        self.assertIn("control content changed", payload["reason"])
        self.assertFalse(temporary_path.exists())

    def test_legacy_short_prefix_receipts_revalidate_linked_back_pointer_bytes(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        linked_source = self.root / "legacy-linked-content-source"
        git(self.repo, "worktree", "add", "--detach", str(linked_source), head)
        linked_admin = pathlib.Path(
            git(linked_source, "rev-parse", "--absolute-git-dir")
        )
        back_pointer = linked_admin / "gitdir"
        original_back_pointer = back_pointer.read_bytes()
        equivalent_back_pointer = f"{linked_source}/./.git\n".encode("utf-8")
        temporary_path = self.root / "legacy-linked-content-drift-view"
        original_capture = named_lane_runtime.run_bounded_capture
        mutated = False

        def mutate_back_pointer(argv: object, **kwargs: object) -> object:
            nonlocal mutated
            command = tuple(argv)
            result = original_capture(command, **kwargs)
            if (
                not mutated
                and f"--git-dir={temporary_path}" in command
                and command[-3:] == ("cat-file", "-t", head)
            ):
                back_pointer.write_bytes(equivalent_back_pointer)
                mutated = True
            return result

        try:
            with mock.patch.object(
                named_lane_runtime,
                "run_bounded_capture",
                side_effect=mutate_back_pointer,
            ):
                returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                    source=linked_source.resolve(),
                    temporary_path=temporary_path,
                    head=head,
                    prefixes=(base[:10],),
                )
        finally:
            back_pointer.write_bytes(original_back_pointer)

        self.assertTrue(mutated)
        self.assertEqual(returncode, 2)
        self.assertEqual(stdout, "")
        payload = json.loads(stderr)
        self.assertEqual(payload["status"], "blocked-safety")
        self.assertIn("control content changed", payload["reason"])
        self.assertFalse(temporary_path.exists())

    def test_legacy_short_prefix_receipts_revalidate_view_content_after_each_query(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        temporary_path = self.root / "legacy-view-config-drift"
        original_capture = named_lane_runtime.run_bounded_capture
        mutated = False

        def mutate_view_config(argv: object, **kwargs: object) -> object:
            nonlocal mutated
            command = tuple(argv)
            result = original_capture(command, **kwargs)
            if (
                not mutated
                and f"--git-dir={temporary_path}" in command
                and command[-3:] == ("cat-file", "-t", head)
            ):
                config = temporary_path / "config"
                config.write_bytes(config.read_bytes() + b"# hostile drift\n")
                mutated = True
            return result

        with mock.patch.object(
            named_lane_runtime,
            "run_bounded_capture",
            side_effect=mutate_view_config,
        ):
            returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                source=self.repo.resolve(),
                temporary_path=temporary_path,
                head=head,
                prefixes=(base[:10],),
            )

        self.assertTrue(mutated)
        self.assertEqual(returncode, 2)
        self.assertEqual(stdout, "")
        payload = json.loads(stderr)
        self.assertEqual(payload["status"], "blocked-safety")
        self.assertIn("view file changed", payload["reason"])
        self.assertFalse(temporary_path.exists())

    def test_legacy_short_prefix_receipts_revalidate_source_object_identity_after_query(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        temporary_path = self.root / "legacy-source-object-replacement-view"
        objects = self.repo / ".git" / "objects"
        original_objects = self.repo / ".git" / "objects.bound-original"
        objects_mode = stat.S_IMODE(objects.lstat().st_mode)
        original_capture = named_lane_runtime.run_bounded_capture
        mutated = False

        def replace_source_objects(argv: object, **kwargs: object) -> object:
            nonlocal mutated
            command = tuple(argv)
            result = original_capture(command, **kwargs)
            if (
                not mutated
                and f"--git-dir={temporary_path}" in command
                and command[-3:] == ("cat-file", "-t", head)
            ):
                objects.rename(original_objects)
                objects.mkdir(mode=objects_mode)
                objects.chmod(objects_mode)
                mutated = True
            return result

        try:
            with mock.patch.object(
                named_lane_runtime,
                "run_bounded_capture",
                side_effect=replace_source_objects,
            ):
                returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                    source=self.repo.resolve(),
                    temporary_path=temporary_path,
                    head=head,
                    prefixes=(base[:10],),
                )
        finally:
            if mutated:
                objects.rmdir()
                original_objects.rename(objects)

        self.assertTrue(mutated)
        self.assertEqual(returncode, 2)
        self.assertEqual(stdout, "")
        payload = json.loads(stderr)
        self.assertEqual(payload["status"], "blocked-safety")
        self.assertIn("object directory changed", payload["reason"])
        self.assertFalse(temporary_path.exists())

    def test_legacy_short_prefix_receipts_accept_unrelated_object_child_churn(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        temporary_path = self.root / "legacy-source-child-churn-view"
        unrelated_payload = self.root / "legacy-unrelated-object"
        unrelated_payload.write_bytes(b"unrelated object child churn\n")
        original_capture = named_lane_runtime.run_bounded_capture
        added_object: str | None = None

        def add_unrelated_object(argv: object, **kwargs: object) -> object:
            nonlocal added_object
            command = tuple(argv)
            result = original_capture(command, **kwargs)
            if (
                added_object is None
                and f"--git-dir={temporary_path}" in command
                and command[-3:] == ("cat-file", "-t", head)
            ):
                added_object = git(
                    self.repo,
                    "hash-object",
                    "-w",
                    str(unrelated_payload),
                )
            return result

        with mock.patch.object(
            named_lane_runtime,
            "run_bounded_capture",
            side_effect=add_unrelated_object,
        ):
            returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                source=self.repo.resolve(),
                temporary_path=temporary_path,
                head=head,
                prefixes=(base[:10],),
            )

        self.assertIsNotNone(added_object)
        self.assertEqual(returncode, 0, stderr)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(
            payload["receipts"][0]["disambiguated_object_ids"],
            [base],
        )
        self.assertFalse(temporary_path.exists())

    def test_legacy_short_prefix_receipts_revalidate_control_access_policy(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        temporary_path = self.root / "legacy-control-mode-drift-view"
        original_capture = named_lane_runtime.run_bounded_capture
        mutated = False

        def mutate_control_tmp(argv: object, **kwargs: object) -> object:
            nonlocal mutated
            command = tuple(argv)
            result = original_capture(command, **kwargs)
            cwd = pathlib.Path(kwargs["cwd"])
            if not mutated and command[-1:] == ("--version",) and cwd.name == "tmp":
                cwd.chmod(0o755)
                mutated = True
            return result

        with mock.patch.object(
            named_lane_runtime,
            "run_bounded_capture",
            side_effect=mutate_control_tmp,
        ):
            returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                source=self.repo.resolve(),
                temporary_path=temporary_path,
                head=head,
                prefixes=(base[:10],),
            )

        self.assertTrue(mutated)
        self.assertEqual(returncode, 2)
        self.assertEqual(stdout, "")
        payload = json.loads(stderr)
        self.assertEqual(payload["status"], "blocked-safety")
        self.assertIn("control child changed", payload["reason"])
        self.assertFalse(temporary_path.exists())
        self.assertEqual(list(self.root.glob(".named-lane-materializer-*")), [])

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "legacy view setup signal transaction requires POSIX pthread_sigmask",
    )
    def test_legacy_short_prefix_receipts_cleanup_signal_after_view_binding(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        temporary_path = self.root / "legacy-view-setup-signal"
        original_make_view = named_lane_runtime._make_legacy_prefix_view
        interrupted = False

        def interrupt_after_view_binding(*args: object, **kwargs: object) -> object:
            nonlocal interrupted
            result = original_make_view(*args, **kwargs)
            interrupted = True
            signal.raise_signal(signal.SIGINT)
            return result

        with mock.patch.object(
            named_lane_runtime,
            "_make_legacy_prefix_view",
            side_effect=interrupt_after_view_binding,
        ):
            returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                source=self.repo.resolve(),
                temporary_path=temporary_path,
                head=head,
                prefixes=(base[:10],),
            )

        self.assertTrue(interrupted)
        self.assertEqual(returncode, 128 + signal.SIGINT)
        self.assertEqual(stdout, "")
        self.assertEqual(
            json.loads(stderr),
            {"status": "blocked-safety", "reason": "forwarded-signal"},
        )
        self.assertFalse(temporary_path.exists())
        self.assertEqual(list(self.root.glob(".named-lane-materializer-*")), [])

    def test_legacy_short_prefix_receipts_cleanup_failure_never_publishes_success(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        temporary_path = self.root / "legacy-retained-view"
        original_rmtree = named_lane_runtime.shutil.rmtree

        def retain_view(path: object, *args: object, **kwargs: object) -> None:
            if pathlib.Path(path) == temporary_path:
                raise OSError("simulated legacy view cleanup failure")
            original_rmtree(path, *args, **kwargs)

        with mock.patch.object(
            named_lane_runtime.shutil,
            "rmtree",
            side_effect=retain_view,
        ):
            returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                source=self.repo.resolve(),
                temporary_path=temporary_path,
                head=head,
                prefixes=(base[:10],),
            )

        self.assertEqual(returncode, 2)
        self.assertEqual(stdout, "")
        payload = json.loads(stderr)
        self.assertEqual(payload["status"], "blocked-safety")
        self.assertIn(
            f"retained legacy prefix temporary path: {temporary_path}",
            payload["reason"],
        )
        self.assertTrue(temporary_path.exists())

    def test_legacy_short_prefix_receipts_commit_signal_during_success_emit(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        temporary_path = self.root / "legacy-receipt-signal-view"
        original_emit = named_lane_runtime._emit
        interrupted = False

        def interrupt_success_emit(
            payload: dict[str, object],
            *,
            stream: object | None = None,
        ) -> None:
            nonlocal interrupted
            if (
                not interrupted
                and payload.get("schema_version")
                == LEGACY_PREFIX_RECEIPT_SCHEMA_VERSION
            ):
                interrupted = True
                signal.raise_signal(signal.SIGINT)
            original_emit(payload, stream=stream)

        with mock.patch.object(
            named_lane_runtime,
            "_emit",
            side_effect=interrupt_success_emit,
        ):
            returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                source=self.repo.resolve(),
                temporary_path=temporary_path,
                head=head,
                prefixes=(base[:10],),
            )

        self.assertTrue(interrupted)
        self.assertEqual(returncode, 0, stderr)
        self.assertEqual(stderr, "")
        self.assertEqual(json.loads(stdout)["status"], "ok")
        self.assertFalse(temporary_path.exists())

    def test_legacy_short_prefix_receipts_emit_failure_never_publishes_success(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        temporary_path = self.root / "legacy-receipt-failure-view"
        original_emit = named_lane_runtime._emit
        receipt_failed = False

        def fail_success_emit(
            payload: dict[str, object],
            *,
            stream: object | None = None,
        ) -> None:
            nonlocal receipt_failed
            if (
                not receipt_failed
                and payload.get("schema_version")
                == LEGACY_PREFIX_RECEIPT_SCHEMA_VERSION
            ):
                receipt_failed = True
                raise BrokenPipeError("simulated legacy receipt failure")
            original_emit(payload, stream=stream)

        with mock.patch.object(
            named_lane_runtime,
            "_emit",
            side_effect=fail_success_emit,
        ):
            returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                source=self.repo.resolve(),
                temporary_path=temporary_path,
                head=head,
                prefixes=(base[:10],),
            )

        self.assertTrue(receipt_failed)
        self.assertEqual(returncode, 2)
        self.assertEqual(stdout, "")
        self.assertEqual(
            json.loads(stderr),
            {
                "status": "blocked-safety",
                "reason": "simulated legacy receipt failure",
            },
        )
        self.assertFalse(temporary_path.exists())

    def test_legacy_short_prefix_receipts_cleanup_parent_drift_reports_descriptor_locator(
        self,
    ) -> None:
        base, _middle, head = self.legacy_prefix_history()
        private_parent = self.root / "legacy-cleanup-parent"
        private_parent.mkdir(mode=0o700)
        private_parent.chmod(0o700)
        original_parent = self.root / "legacy-cleanup-parent.bound-original"
        temporary_path = private_parent / "legacy-parent-drift-view"
        original_rmtree = named_lane_runtime.shutil.rmtree
        drifted = False

        def drift_parent(path: object, *args: object, **kwargs: object) -> None:
            nonlocal drifted
            if not drifted and pathlib.Path(path) == temporary_path:
                private_parent.rename(original_parent)
                private_parent.mkdir(mode=0o700)
                private_parent.chmod(0o700)
                drifted = True
                raise OSError("simulated parent replacement during cleanup")
            original_rmtree(path, *args, **kwargs)

        try:
            with mock.patch.object(
                named_lane_runtime.shutil,
                "rmtree",
                side_effect=drift_parent,
            ):
                returncode, stdout, stderr = self.invoke_legacy_prefix_cli(
                    source=self.repo.resolve(),
                    temporary_path=temporary_path,
                    head=head,
                    prefixes=(base[:10],),
                )
        finally:
            if drifted:
                private_parent.rmdir()
                original_parent.rename(private_parent)

        self.assertTrue(drifted)
        self.assertEqual(returncode, 2)
        self.assertEqual(stdout, "")
        payload = json.loads(stderr)
        self.assertEqual(payload["status"], "blocked-safety")
        self.assertIn(
            "retained legacy prefix temporary locator: parent device=",
            payload["reason"],
        )
        self.assertIn("leaf=legacy-parent-drift-view", payload["reason"])
        self.assertNotIn(str(temporary_path), payload["reason"])

    def test_parent_graph_output_limit_uses_exact_hash_width_formula(self) -> None:
        limit = named_lane_runtime.MATERIALIZER_PARENT_EDGE_COUNT_LIMIT
        self.assertEqual(
            named_lane_runtime._parent_graph_output_limit(3, 40),
            (3 + limit) * 41,
        )
        self.assertEqual(
            named_lane_runtime._parent_graph_output_limit(3, 64),
            (3 + limit) * 65,
        )

    def test_parent_graph_edge_boundary_counts_duplicate_parent_tokens(self) -> None:
        base = b"1" * 40
        head = b"2" * 40
        payload = head + b" " + base + b" " + base + b"\n" + base + b"\n"
        expected_commits = frozenset((base, head))

        with mock.patch.object(
            named_lane_runtime,
            "MATERIALIZER_PARENT_EDGE_COUNT_LIMIT",
            2,
        ):
            counts = named_lane_runtime._parse_parent_graph(
                payload,
                expected_commits,
                base,
                40,
                label="test parent graph",
                scope_mismatch_message="scope mismatch",
            )

        self.assertEqual(counts.commit_count, 2)
        self.assertEqual(counts.parent_edge_count, 2)
        canonical = (
            b"named-lane-parent-graph-v1\0"
            b"40\0" + base + b"\0\n" + head + b"\0" + base + b"\0" + base + b"\0\n"
        )
        self.assertEqual(
            counts.parent_graph_sha256,
            hashlib.sha256(canonical).hexdigest(),
        )
        with (
            mock.patch.object(
                named_lane_runtime,
                "MATERIALIZER_PARENT_EDGE_COUNT_LIMIT",
                1,
            ),
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "parent-edge budget",
            ),
        ):
            named_lane_runtime._parse_parent_graph(
                payload,
                expected_commits,
                base,
                40,
                label="test parent graph",
                scope_mismatch_message="scope mismatch",
            )

    def test_parent_graph_digest_preserves_merge_parent_order(self) -> None:
        base = b"1" * 40
        left = b"2" * 40
        right = b"3" * 40
        head = b"4" * 40
        expected_commits = frozenset((base, left, right, head))
        common_rows = left + b" " + base + b"\n" + right + b" " + base + b"\n"
        left_right = named_lane_runtime._parse_parent_graph(
            head + b" " + left + b" " + right + b"\n" + common_rows + base + b"\n",
            expected_commits,
            base,
            40,
            label="left-right graph",
            scope_mismatch_message="scope mismatch",
        )
        right_left = named_lane_runtime._parse_parent_graph(
            base + b"\n" + common_rows + head + b" " + right + b" " + left + b"\n",
            expected_commits,
            base,
            40,
            label="right-left graph",
            scope_mismatch_message="scope mismatch",
        )

        self.assertEqual(left_right.commit_count, right_left.commit_count)
        self.assertEqual(left_right.parent_edge_count, right_left.parent_edge_count)
        self.assertNotEqual(
            left_right.parent_graph_sha256,
            right_left.parent_graph_sha256,
        )

    def test_small_merge_parent_edge_budget_is_shared_and_fails_before_pack(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        tree = git(self.repo, "rev-parse", f"{base}^{{tree}}")
        left = git(self.repo, "commit-tree", tree, "-p", base, "-m", "left")
        right = git(self.repo, "commit-tree", tree, "-p", base, "-m", "right")
        head = git(
            self.repo,
            "commit-tree",
            tree,
            "-p",
            left,
            "-p",
            right,
            "-m",
            "merge",
        )
        git(self.repo, "update-ref", "refs/heads/master", head, base)
        destination = self.root / "parent-budget-merge-lane"
        original_capture = named_lane_runtime.run_bounded_capture

        with (
            mock.patch.object(
                named_lane_runtime,
                "MATERIALIZER_PARENT_EDGE_COUNT_LIMIT",
                4,
            ),
            mock.patch.object(
                named_lane_runtime,
                "run_bounded_capture",
                wraps=original_capture,
            ) as capture,
        ):
            materialized = materialize_worktree(
                self.repo.resolve(),
                destination,
                base,
                head,
            )
            validated = validate_worktree(destination, base, head)

        self.assertEqual(materialized.commit_count, 4)
        self.assertEqual(materialized.parent_edge_count, 4)
        self.assertEqual(validated.commit_count, 4)
        self.assertEqual(validated.parent_edge_count, 4)
        self.assertEqual(
            materialized.parent_graph_sha256,
            validated.parent_graph_sha256,
        )
        self.assertEqual(
            materialized.local_config_sha256,
            validated.local_config_sha256,
        )
        self.assertRegex(materialized.parent_graph_sha256, r"\A[0-9a-f]{64}\Z")
        self.assertRegex(materialized.local_config_sha256, r"\A[0-9a-f]{64}\Z")
        parent_calls = [
            call
            for call in capture.call_args_list
            if "rev-list" in tuple(call.args[0]) and "--parents" in tuple(call.args[0])
        ]
        self.assertEqual(len(parent_calls), 2)
        expected_output_limit = (4 + 4) * (len(head) + 1)
        self.assertTrue(
            all(
                call.kwargs["stdout_limit_bytes"] == expected_output_limit
                for call in parent_calls
            )
        )

        rejected_destination = self.root / "parent-budget-rejected-lane"
        with (
            mock.patch.object(
                named_lane_runtime,
                "MATERIALIZER_PARENT_EDGE_COUNT_LIMIT",
                3,
            ),
            mock.patch.object(
                named_lane_runtime,
                "run_bounded_capture",
                wraps=original_capture,
            ) as rejected_capture,
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "parent-edge budget",
            ),
        ):
            materialize_worktree(
                self.repo.resolve(),
                rejected_destination,
                base,
                head,
            )

        rejected_commands = [
            tuple(call.args[0]) for call in rejected_capture.call_args_list
        ]
        self.assertFalse(
            any("pack-objects" in command for command in rejected_commands)
        )
        self.assertFalse(rejected_destination.exists())
        with (
            mock.patch.object(
                named_lane_runtime,
                "MATERIALIZER_PARENT_EDGE_COUNT_LIMIT",
                3,
            ),
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "parent-edge budget",
            ),
        ):
            validate_worktree(destination, base, head)

    def test_materializer_checks_out_exact_head_without_running_status(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        (self.repo / "unrelated-large.bin").write_bytes(os.urandom(2 * 1024 * 1024))
        unrelated_head = self.commit("unrelated side history")
        unrelated_blob = git(
            self.repo,
            "rev-parse",
            f"{unrelated_head}:unrelated-large.bin",
        )
        git(self.repo, "branch", "unrelated-side", unrelated_head)
        git(self.repo, "reset", "--hard", head)
        destination = self.root / "lane"
        original_capture = named_lane_runtime.run_bounded_capture

        with mock.patch.object(
            named_lane_runtime,
            "run_bounded_capture",
            wraps=original_capture,
        ) as capture:
            with mock.patch.object(
                named_lane_runtime,
                "MATERIALIZER_PACK_BYTES_LIMIT",
                128 * 1024,
            ):
                result = materialize_worktree(
                    self.repo.resolve(),
                    destination,
                    base,
                    head,
                )

        self.assertEqual(result.root, destination)
        self.assertEqual(result.base_sha, base)
        self.assertEqual(result.head_sha, head)
        self.assertEqual(result.commit_count, 2)
        self.assertEqual(result.parent_edge_count, 1)
        self.assertRegex(result.parent_graph_sha256, r"\A[0-9a-f]{64}\Z")
        self.assertRegex(result.local_config_sha256, r"\A[0-9a-f]{64}\Z")
        self.assertEqual(git(destination, "rev-parse", "HEAD"), head)
        self.assertEqual(
            git(destination, "rev-parse", MATERIALIZER_BASE_REF),
            base,
        )
        self.assertEqual(
            git(destination, "rev-parse", MATERIALIZER_HEAD_REF),
            head,
        )
        self.assertNotIn(
            "remote.origin.url",
            git(destination, "config", "--local", "--name-only", "--list"),
        )
        local_config_keys = git(
            destination,
            "config",
            "--local",
            "--name-only",
            "--list",
        ).splitlines()
        self.assertFalse(
            any(key.casefold().startswith("remote.") for key in local_config_keys)
        )
        self.assertFalse(
            any(
                key.casefold() == "extensions.partialclone" for key in local_config_keys
            )
        )
        self.assertEqual(
            git(
                destination,
                "config",
                "--local",
                "--type=bool",
                "--get",
                "core.commitGraph",
            ),
            "false",
        )
        self.assertEqual(
            git(
                destination,
                "config",
                "--local",
                "--type=bool",
                "--get",
                "core.multiPackIndex",
            ),
            "false",
        )
        tracked_blob = git(self.repo, "rev-parse", f"{head}:tracked.txt")
        git(destination, "cat-file", "-e", tracked_blob)
        for unrelated_object in (unrelated_head, unrelated_blob):
            absent = subprocess.run(
                (
                    "git",
                    "-C",
                    str(destination),
                    "cat-file",
                    "-e",
                    unrelated_object,
                ),
                check=False,
                env={
                    **os.environ,
                    "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_SYSTEM": os.devnull,
                    "GIT_NO_LAZY_FETCH": "1",
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(absent.returncode, 0)
        self.assertNotIn(
            "refs/heads/unrelated-side",
            git(destination, "for-each-ref", "--format=%(refname)").splitlines(),
        )
        validated = validate_worktree(destination, base, head)
        self.assertEqual(validated.head_sha, head)
        self.assertEqual(validated.commit_count, 2)
        self.assertEqual(validated.parent_edge_count, 1)
        self.assertEqual(result.parent_graph_sha256, validated.parent_graph_sha256)
        self.assertEqual(result.local_config_sha256, validated.local_config_sha256)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
        self.assertEqual(
            list(self.root.glob(".named-lane-materializer-*")),
            [],
        )

        commands = [tuple(call.args[0]) for call in capture.call_args_list]
        for command in commands:
            self.assertTrue({"status", "diff-files", "diff-index"}.isdisjoint(command))
            if command[-1:] != ("--version",):
                commit_graph_index = command.index("core.commitGraph=false")
                self.assertEqual(command[commit_graph_index - 1], "-c")
                check_stat_index = command.index("core.checkStat=default")
                self.assertEqual(command[check_stat_index - 1], "-c")
                ignore_stat_index = command.index("core.ignoreStat=false")
                self.assertEqual(command[ignore_stat_index - 1], "-c")
                multi_pack_index = command.index("core.multiPackIndex=false")
                self.assertEqual(command[multi_pack_index - 1], "-c")
                trust_ctime_index = command.index("core.trustCtime=true")
                self.assertEqual(command[trust_ctime_index - 1], "-c")
        for forbidden in ("clone", "fetch", "upload-pack"):
            self.assertFalse(any(forbidden in command for command in commands))
        init = next(command for command in commands if "init" in command)
        self.assertIn("--object-format=sha1", init)
        self.assertTrue(any(item.startswith("--template=") for item in init))
        pack = next(command for command in commands if "pack-objects" in command)
        self.assertIn("--stdout", pack)
        self.assertIn("--no-reuse-delta", pack)
        self.assertIn("--no-reuse-object", pack)
        self.assertIn("--no-use-bitmap-index", pack)
        self.assertNotIn("--revs", pack)
        self.assertNotIn("--all", pack)
        index_pack = next(command for command in commands if "index-pack" in command)
        self.assertIn("--stdin", index_pack)
        self.assertIn("--strict", index_pack)
        self.assertTrue(
            any(item.startswith("--max-input-size=") for item in index_pack)
        )
        init_call = next(
            call for call in capture.call_args_list if "init" in tuple(call.args[0])
        )
        init_environment = init_call.kwargs["env"]
        materializer_cwd = pathlib.Path(init_call.kwargs["cwd"])
        self.assertEqual(materializer_cwd.name, "tmp")
        self.assertTrue(
            materializer_cwd.parent.name.startswith(".named-lane-materializer-")
        )
        self.assertEqual(materializer_cwd.parent.parent, self.root)
        for call in capture.call_args_list:
            self.assertEqual(pathlib.Path(call.kwargs["cwd"]), materializer_cwd)
            self.assertEqual(
                call.kwargs["env"]["GIT_CEILING_DIRECTORIES"],
                str(destination.parent),
            )
        self.assertEqual(
            set(init_environment),
            {
                "GIT_ASKPASS",
                "GIT_ATTR_NOSYSTEM",
                "GIT_CEILING_DIRECTORIES",
                "GIT_CONFIG_GLOBAL",
                "GIT_CONFIG_NOSYSTEM",
                "GIT_CONFIG_SYSTEM",
                "GIT_GRAFT_FILE",
                "GIT_NO_LAZY_FETCH",
                "GIT_NO_REPLACE_OBJECTS",
                "GIT_OPTIONAL_LOCKS",
                "GIT_PAGER",
                "GIT_TERMINAL_PROMPT",
                "HOME",
                "LANG",
                "LC_ALL",
                "PAGER",
                "PATH",
                "XDG_CONFIG_HOME",
            },
        )
        self.assertEqual(init_environment["GIT_ASKPASS"], "/usr/bin/false")
        self.assertEqual(
            init_environment["GIT_CEILING_DIRECTORIES"],
            str(destination.parent),
        )
        self.assertEqual(init_environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(init_environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(init_environment["GIT_CONFIG_SYSTEM"], os.devnull)
        self.assertEqual(init_environment["GIT_GRAFT_FILE"], os.devnull)
        self.assertEqual(init_environment["GIT_ATTR_NOSYSTEM"], "1")
        self.assertEqual(init_environment["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(init_environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(init_environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(init_environment["GIT_OPTIONAL_LOCKS"], "0")
        self.assertEqual(init_environment["GIT_PAGER"], "cat")
        self.assertEqual(init_environment["PAGER"], "cat")
        self.assertNotIn("GIT_TEMPLATE_DIR", init_environment)
        self.assertNotIn("TMPDIR", init_environment)
        self.assertNotEqual(init_environment["HOME"], str(pathlib.Path.home()))
        self.assertNotEqual(
            init_environment["XDG_CONFIG_HOME"],
            os.environ.get("XDG_CONFIG_HOME"),
        )
        pack_call = next(
            call
            for call in capture.call_args_list
            if "pack-objects" in tuple(call.args[0])
        )
        self.assertEqual(
            pack_call.kwargs["env"]["GIT_ALTERNATE_OBJECT_DIRECTORIES"],
            str((self.repo / ".git" / "objects").resolve()),
        )
        self.assertFalse(
            any(
                str(self.repo.resolve()) in argument
                for command in commands
                for argument in command
            )
        )

    def test_materializer_imports_only_the_exact_shallow_range_closure(self) -> None:
        (self.repo / "AGENTS.md").write_text("pre-base\n", encoding="utf-8")
        pre_base_only = self.repo / "pre-base-only.txt"
        pre_base_only.write_text("pre-base payload\n", encoding="utf-8")
        pre_base = self.commit("pre-base")
        pre_base_tree = git(self.repo, "rev-parse", f"{pre_base}^{{tree}}")
        pre_base_blob = git(
            self.repo,
            "rev-parse",
            f"{pre_base}:pre-base-only.txt",
        )

        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        pre_base_only.unlink()
        (self.repo / "base-only.txt").write_text("base payload\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "middle.txt").write_text("middle payload\n", encoding="utf-8")
        middle = self.commit("middle")
        (self.repo / "head.txt").write_text("head payload\n", encoding="utf-8")
        head = self.commit("head")
        destination = self.root / "exact-shallow-range-lane"
        source_shallow = self.repo / ".git" / "shallow"

        self.assertFalse(source_shallow.exists())
        self.assertEqual(
            git(self.repo, "rev-parse", "--is-shallow-repository"),
            "false",
        )

        result = materialize_worktree(
            self.repo.resolve(),
            destination,
            base,
            head,
        )

        self.assertEqual(result.base_sha, base)
        self.assertEqual(result.head_sha, head)
        self.assertFalse(source_shallow.exists())
        self.assertEqual(
            git(self.repo, "rev-parse", "--is-shallow-repository"),
            "false",
        )
        shallow = destination / ".git" / "shallow"
        shallow_metadata = shallow.lstat()
        self.assertTrue(stat.S_ISREG(shallow_metadata.st_mode))
        self.assertFalse(shallow.is_symlink())
        self.assertEqual(shallow_metadata.st_uid, os.getuid())
        self.assertEqual(stat.S_IMODE(shallow_metadata.st_mode), 0o600)
        self.assertEqual(shallow_metadata.st_nlink, 1)
        self.assertEqual(shallow.read_bytes(), f"{base}\n".encode("ascii"))
        self.assertEqual(
            git(destination, "rev-parse", "--is-shallow-repository"),
            "true",
        )

        expected_objects = set(
            git(
                self.repo,
                "rev-list",
                "--objects",
                "--no-object-names",
                "--no-walk",
                base,
                middle,
                head,
            ).splitlines()
        )
        actual_objects = set(
            git(
                destination,
                "cat-file",
                "--batch-check=%(objectname)",
                "--batch-all-objects",
                "--unordered",
            ).splitlines()
        )
        self.assertEqual(actual_objects, expected_objects)
        for label, object_id in (
            ("commit", pre_base),
            ("tree", pre_base_tree),
            ("blob", pre_base_blob),
        ):
            with self.subTest(pre_base_object=label):
                self.assertNotIn(object_id, actual_objects)

        self.assertEqual(validate_worktree(destination, base, head).head_sha, head)
        self.assertEqual(
            set(
                git(
                    destination,
                    "diff",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--name-only",
                    f"{base}..{head}",
                    "--",
                ).splitlines()
            ),
            {"head.txt", "middle.txt"},
        )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "pack ownership handoff requires POSIX pthread_sigmask",
    )
    def test_materializer_pack_handoff_signal_wipes_published_payload(self) -> None:
        class AuditedPack(bytearray):
            before_clear: bytes | None = None

            def clear(self) -> None:
                self.before_clear = bytes(self)
                super().clear()

        payload = AuditedPack(b"sensitive-pack-payload")
        capture = mock.Mock(
            returncode=0,
            stdout=payload,
            stderr=bytearray(b"pack stderr"),
        )
        owner = named_lane_runtime._MaterializerPackPayloadOwner()
        original_write = named_lane_runtime._write_materializer_pack_zero_chunk
        signal_injected = False
        cleanup_signal_injected = False

        def capture_then_signal(*_args: object, **_kwargs: object) -> object:
            nonlocal signal_injected
            signal_injected = True
            signal.raise_signal(signal.SIGTERM)
            return capture

        def write_then_signal(
            view: memoryview,
            offset: int,
            chunk_size: int,
            zeroes: bytes,
        ) -> None:
            nonlocal cleanup_signal_injected
            original_write(view, offset, chunk_size, zeroes)
            if not cleanup_signal_injected:
                cleanup_signal_injected = True
                signal.raise_signal(signal.SIGINT)

        with (
            mock.patch.object(
                named_lane_runtime,
                "run_bounded_capture",
                side_effect=capture_then_signal,
            ),
            mock.patch.object(
                named_lane_runtime,
                "_write_materializer_pack_zero_chunk",
                side_effect=write_then_signal,
            ),
            self.assertRaises(ForwardedSignal) as raised,
        ):
            with named_lane_runtime._structured_forwarded_signals():
                try:
                    named_lane_runtime._materializer_pack_manifest(
                        self.repo,
                        bytearray(b"manifest\n"),
                        pathlib.Path("/usr/bin/git"),
                        {},
                        self.root / "hooks",
                        owner,
                    )
                finally:
                    owner.zeroize(primary_error=sys.exc_info()[1])

        self.assertTrue(signal_injected)
        self.assertTrue(cleanup_signal_injected)
        self.assertEqual(raised.exception.signum, signal.SIGTERM)
        self.assertEqual(payload.before_clear, b"\x00" * 22)
        self.assertEqual(payload, bytearray())
        self.assertIsNone(owner.payload)
        self.assertEqual(capture.stderr, bytearray(b"\x00" * 11))

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "pack capture cleanup requires POSIX pthread_sigmask",
    )
    def test_materializer_pack_failure_wipes_stdout_before_stderr_error(self) -> None:
        class AuditedPack(bytearray):
            before_clear: bytes | None = None

            def clear(self) -> None:
                self.before_clear = bytes(self)
                super().clear()

        class FailingStderr(bytearray):
            def __setitem__(self, key: object, value: object) -> None:
                raise MemoryError("synthetic stderr wipe failure")

        payload = AuditedPack(b"failed-pack-payload")
        capture = mock.Mock(
            returncode=1,
            stdout=payload,
            stderr=FailingStderr(b"failure detail"),
        )
        owner = named_lane_runtime._MaterializerPackPayloadOwner()
        mask_before = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        runner_mask: set[signal.Signals] | None = None

        def return_failed_capture(*_args: object, **_kwargs: object) -> object:
            nonlocal runner_mask
            runner_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
            return capture

        with (
            mock.patch.object(
                named_lane_runtime,
                "run_bounded_capture",
                side_effect=return_failed_capture,
            ),
            self.assertRaisesRegex(MemoryError, "stderr wipe failure"),
        ):
            named_lane_runtime._materializer_pack_manifest(
                self.repo,
                bytearray(b"manifest\n"),
                pathlib.Path("/usr/bin/git"),
                {},
                self.root / "hooks",
                owner,
            )

        self.assertIsNotNone(runner_mask)
        self.assertTrue(set(named_lane_runtime.forwarded_signals()) <= runner_mask)
        self.assertEqual(
            signal.pthread_sigmask(signal.SIG_BLOCK, set()),
            mask_before,
        )
        self.assertEqual(payload.before_clear, b"\x00" * 19)
        self.assertEqual(payload, bytearray())
        self.assertIsNone(owner.payload)

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "pack capture cleanup requires POSIX pthread_sigmask",
    )
    def test_materializer_pack_failure_survives_signal_during_final_restore(
        self,
    ) -> None:
        class AuditedPack(bytearray):
            before_clear: bytes | None = None

            def clear(self) -> None:
                self.before_clear = bytes(self)
                super().clear()

        payload = AuditedPack(b"failed-pack-payload")
        capture = mock.Mock(
            returncode=1,
            stdout=payload,
            stderr=bytearray(b"failure detail"),
        )
        owner = named_lane_runtime._MaterializerPackPayloadOwner()
        previous_handler = signal.getsignal(signal.SIGTERM)
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        real_restore = named_lane_runtime.restore_signal_mask
        restore_calls = 0

        def interrupt_final_restore(
            mask: set[signal.Signals] | None,
        ) -> None:
            nonlocal restore_calls
            restore_calls += 1
            if restore_calls == 2:
                signal.raise_signal(signal.SIGTERM)
            real_restore(mask)

        with named_lane_runtime._structured_forwarded_signals():
            with (
                mock.patch.object(
                    named_lane_runtime,
                    "run_bounded_capture",
                    return_value=capture,
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "restore_signal_mask",
                    side_effect=interrupt_final_restore,
                ),
                self.assertRaisesRegex(
                    NamedLaneGuardError,
                    "bounded materializer Git pack-objects failed",
                ),
            ):
                named_lane_runtime._materializer_pack_manifest(
                    self.repo,
                    bytearray(b"manifest\n"),
                    pathlib.Path("/usr/bin/git"),
                    {},
                    self.root / "hooks",
                    owner,
                )

        self.assertEqual(restore_calls, 2)
        self.assertEqual(payload.before_clear, b"\x00" * 19)
        self.assertEqual(payload, bytearray())
        self.assertEqual(capture.stderr, bytearray(b"\x00" * 14))
        self.assertIsNone(owner.payload)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous_handler)
        self.assertEqual(
            signal.pthread_sigmask(signal.SIG_BLOCK, set()),
            previous_mask,
        )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "pack zeroization requires POSIX pthread_sigmask",
    )
    def test_materializer_pack_wipe_defers_signal_until_full_clear(self) -> None:
        class AuditedPack(bytearray):
            before_clear: bytes | None = None

            def clear(self) -> None:
                self.before_clear = bytes(self)
                super().clear()

        payload_size = 2 * 64 * 1024 + 17
        payload = AuditedPack(b"p" * payload_size)
        original_write = named_lane_runtime._write_materializer_pack_zero_chunk
        chunks = 0

        def write_then_signal(
            view: memoryview,
            offset: int,
            chunk_size: int,
            zeroes: bytes,
        ) -> None:
            nonlocal chunks
            original_write(view, offset, chunk_size, zeroes)
            chunks += 1
            if chunks == 1:
                signal.raise_signal(signal.SIGINT)

        with (
            mock.patch.object(
                named_lane_runtime,
                "_write_materializer_pack_zero_chunk",
                side_effect=write_then_signal,
            ),
            self.assertRaises(ForwardedSignal) as raised,
        ):
            with named_lane_runtime._structured_forwarded_signals():
                named_lane_runtime._zeroize_materializer_pack(payload)

        self.assertEqual(raised.exception.signum, signal.SIGINT)
        self.assertEqual(chunks, 3)
        self.assertEqual(payload.before_clear, b"\x00" * payload_size)
        self.assertEqual(payload, bytearray())

    def test_materializer_rejects_a_merge_parent_outside_the_exact_shallow_range(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("pre-base\n", encoding="utf-8")
        pre_base = self.commit("pre-base")
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "selected.txt").write_text("selected\n", encoding="utf-8")
        selected_parent = self.commit("selected parent")
        selected_tree = git(
            self.repo,
            "rev-parse",
            f"{selected_parent}^{{tree}}",
        )
        head = git(
            self.repo,
            "commit-tree",
            selected_tree,
            "-p",
            selected_parent,
            "-p",
            pre_base,
            "-m",
            "selected merge",
        )
        git(
            self.repo,
            "update-ref",
            "refs/heads/master",
            head,
            selected_parent,
        )
        exact_commits = {
            base,
            *git(self.repo, "rev-list", head, f"^{base}", "--").splitlines(),
        }
        selected_parents = set(git(self.repo, "rev-parse", f"{head}^@").splitlines())
        destination = self.root / "invalid-shallow-merge-lane"

        self.assertIn(head, exact_commits)
        self.assertIn(pre_base, selected_parents)
        self.assertNotIn(pre_base, exact_commits)
        self.assertFalse((self.repo / ".git" / "shallow").exists())
        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "materializer shallow commit closure does not match "
            "the frozen source range",
        ):
            materialize_worktree(
                self.repo.resolve(),
                destination,
                base,
                head,
            )

        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".named-lane-materializer-*")), [])
        self.assertFalse((self.repo / ".git" / "shallow").exists())

    def test_materializer_rejects_off_corridor_unrelated_root_history(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "selected.txt").write_text("selected\n", encoding="utf-8")
        selected_parent = self.commit("selected parent")
        selected_tree = git(self.repo, "rev-parse", f"{selected_parent}^{{tree}}")
        unrelated_root = git(
            self.repo,
            "commit-tree",
            selected_tree,
            "-m",
            "unrelated root",
        )
        head = git(
            self.repo,
            "commit-tree",
            selected_tree,
            "-p",
            selected_parent,
            "-p",
            unrelated_root,
            "-m",
            "off-corridor merge",
        )
        git(self.repo, "update-ref", "refs/heads/master", head, selected_parent)
        destination = self.root / "off-corridor-root-lane"

        self.assertEqual(
            git(self.repo, "merge-base", "--all", base, head),
            base,
        )
        self.assertIn(
            unrelated_root,
            git(self.repo, "rev-list", head, f"^{base}", "--").splitlines(),
        )
        self.assertNotIn(
            unrelated_root,
            git(
                self.repo,
                "rev-list",
                "--ancestry-path",
                head,
                f"^{base}",
                "--",
            ).splitlines(),
        )
        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "materializer review graph cannot be represented by "
            "the sole shallow boundary",
        ):
            materialize_worktree(
                self.repo.resolve(),
                destination,
                base,
                head,
            )

        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".named-lane-materializer-*")), [])
        self.assertFalse((self.repo / ".git" / "shallow").exists())

    def test_materializer_revalidates_shallow_content_and_policy_across_pack(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        base_payload = f"{base}\n".encode("ascii")
        head_payload = f"{head}\n".encode("ascii")
        self.assertEqual(len(base_payload), len(head_payload))
        original_capture = named_lane_runtime.run_bounded_capture
        cases = (
            (
                "same-size-content-after-pack",
                "pack-objects",
                "materialized Git shallow boundary changed during inspection",
            ),
            (
                "mode-after-index",
                "index-pack",
                "materialized Git shallow boundary is not safe",
            ),
        )

        for label, trigger, expected in cases:
            with self.subTest(label=label):
                destination = self.root / f"shallow-revalidation-{label}-lane"
                shallow = destination / ".git" / "shallow"
                injected = False

                def mutate_after_stage(argv: object, **kwargs: object) -> object:
                    nonlocal injected
                    command = tuple(argv)
                    result = original_capture(command, **kwargs)
                    if injected or trigger not in command:
                        return result

                    before = shallow.lstat()
                    before_payload = shallow.read_bytes()
                    self.assertEqual(before_payload, base_payload)
                    self.assertTrue(stat.S_ISREG(before.st_mode))
                    self.assertEqual(stat.S_IMODE(before.st_mode), 0o600)
                    self.assertEqual(before.st_nlink, 1)
                    if label == "same-size-content-after-pack":
                        shallow.write_bytes(head_payload)
                    else:
                        shallow.chmod(0o644)
                    after = shallow.lstat()
                    self.assertEqual(
                        (after.st_dev, after.st_ino),
                        (before.st_dev, before.st_ino),
                    )
                    self.assertEqual(after.st_size, before.st_size)
                    if label == "same-size-content-after-pack":
                        self.assertEqual(shallow.read_bytes(), head_payload)
                        self.assertEqual(stat.S_IMODE(after.st_mode), 0o600)
                    else:
                        self.assertEqual(shallow.read_bytes(), base_payload)
                        self.assertEqual(stat.S_IMODE(after.st_mode), 0o644)
                    injected = True
                    return result

                with mock.patch.object(
                    named_lane_runtime,
                    "run_bounded_capture",
                    side_effect=mutate_after_stage,
                ):
                    with self.assertRaisesRegex(NamedLaneGuardError, expected):
                        materialize_worktree(
                            self.repo.resolve(),
                            destination,
                            base,
                            head,
                        )

                self.assertTrue(injected)
                self.assertFalse(destination.exists())
                self.assertEqual(
                    list(self.root.glob(".named-lane-materializer-*")),
                    [],
                )

    def test_materializer_allows_safe_shallow_replacement_between_stages(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        destination = self.root / "safe-shallow-replacement-lane"
        shallow = destination / ".git" / "shallow"
        expected_payload = f"{base}\n".encode("ascii")
        original_capture = named_lane_runtime.run_bounded_capture
        identities: list[tuple[int, int]] = []
        replaced = False

        def replace_after_pack(argv: object, **kwargs: object) -> object:
            nonlocal replaced
            command = tuple(argv)
            result = original_capture(command, **kwargs)
            if replaced or "pack-objects" not in command:
                return result

            before = shallow.lstat()
            self.assertEqual(shallow.read_bytes(), expected_payload)
            replacement = shallow.with_name("shallow.replacement")
            replacement.write_bytes(expected_payload)
            replacement.chmod(0o600)
            replacement_metadata = replacement.lstat()
            self.assertTrue(stat.S_ISREG(replacement_metadata.st_mode))
            self.assertEqual(replacement_metadata.st_uid, before.st_uid)
            self.assertEqual(stat.S_IMODE(replacement_metadata.st_mode), 0o600)
            self.assertEqual(replacement_metadata.st_nlink, 1)
            identities.append((before.st_dev, before.st_ino))
            os.replace(replacement, shallow)
            after = shallow.lstat()
            identities.append((after.st_dev, after.st_ino))
            self.assertEqual(shallow.read_bytes(), expected_payload)
            self.assertEqual(stat.S_IMODE(after.st_mode), 0o600)
            self.assertEqual(after.st_nlink, 1)
            replaced = True
            return result

        with mock.patch.object(
            named_lane_runtime,
            "run_bounded_capture",
            side_effect=replace_after_pack,
        ):
            result = materialize_worktree(
                self.repo.resolve(),
                destination,
                base,
                head,
            )

        self.assertTrue(replaced)
        self.assertEqual(result.head_sha, head)
        self.assertEqual(len(identities), 2)
        self.assertNotEqual(identities[0], identities[1])
        self.assertEqual(shallow.read_bytes(), expected_payload)
        self.assertEqual(validate_worktree(destination, base, head).head_sha, head)
        self.assertEqual(list(self.root.glob(".named-lane-materializer-*")), [])

    def test_materializer_ignores_a_forged_source_commit_graph(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "head-only.txt").write_text("head only\n", encoding="utf-8")
        head = self.commit("head")
        base_tree = bytes.fromhex(git(self.repo, "rev-parse", f"{base}^{{tree}}"))
        git(self.repo, "commit-graph", "write", "--reachable")
        graph_path = self.repo / ".git" / "objects" / "info" / "commit-graph"
        graph = bytearray(graph_path.read_bytes())
        self.assertEqual(graph[:4], b"CGPH")
        hash_length = {1: 20, 2: 32}[graph[5]]
        chunk_count = graph[6]
        chunks: dict[bytes, int] = {}
        for index in range(chunk_count + 1):
            entry = 8 + index * 12
            chunk_id = bytes(graph[entry : entry + 4])
            chunk_offset = int.from_bytes(graph[entry + 4 : entry + 12], "big")
            if chunk_id != b"\0\0\0\0":
                chunks[chunk_id] = chunk_offset
        oid_fanout = chunks[b"OIDF"]
        oid_lookup = chunks[b"OIDL"]
        commit_data = chunks[b"CDAT"]
        commit_count = int.from_bytes(
            graph[oid_fanout + 255 * 4 : oid_fanout + 256 * 4],
            "big",
        )
        head_bytes = bytes.fromhex(head)
        position = next(
            index
            for index in range(commit_count)
            if bytes(
                graph[
                    oid_lookup + index * hash_length : oid_lookup
                    + (index + 1) * hash_length
                ]
            )
            == head_bytes
        )
        record = commit_data + position * (hash_length + 16)
        graph[record : record + hash_length] = base_tree
        digest_name = "sha1" if hash_length == 20 else "sha256"
        graph[-hash_length:] = hashlib.new(
            digest_name,
            graph[:-hash_length],
        ).digest()
        graph_path.chmod(0o600)
        graph_path.write_bytes(graph)
        verification = subprocess.run(
            ("git", "-C", str(self.repo), "commit-graph", "verify"),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(verification.returncode, 0)

        destination = self.root / "forged-commit-graph-lane"
        result = materialize_worktree(
            self.repo.resolve(),
            destination,
            base,
            head,
        )

        self.assertEqual(result.head_sha, head)
        self.assertEqual(
            (destination / "head-only.txt").read_text(encoding="utf-8"),
            "head only\n",
        )
        self.assertFalse(
            (destination / ".git" / "objects" / "info" / "commit-graph").is_file()
        )
        self.assertEqual(
            git(
                destination,
                "config",
                "--local",
                "--type=bool",
                "--get",
                "core.commitGraph",
            ),
            "false",
        )
        self.assertEqual(validate_worktree(destination, base, head).head_sha, head)

    def test_materializer_rejects_source_pack_bitmap_before_object_traversal(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        git(self.repo, "repack", "-a", "-d", "-b")
        source_bitmaps = tuple(
            (self.repo / ".git" / "objects" / "pack").glob("*.bitmap")
        )
        self.assertTrue(source_bitmaps)
        destination = self.root / "bitmap-free-lane"
        commands: list[tuple[str, ...]] = []
        original_capture = named_lane_runtime.run_bounded_capture

        def capture_command(argv: object, **kwargs: object) -> object:
            commands.append(tuple(str(item) for item in argv))
            return original_capture(argv, **kwargs)

        with (
            mock.patch.object(
                named_lane_runtime,
                "run_bounded_capture",
                side_effect=capture_command,
            ),
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "source Git bitmap cache is not allowed",
            ),
        ):
            materialize_worktree(
                self.repo.resolve(),
                destination,
                base,
                head,
            )

        self.assertFalse(destination.exists())
        self.assertEqual(
            tuple((self.repo / ".git" / "objects" / "pack").glob("*.bitmap")),
            source_bitmaps,
        )
        forbidden = {"rev-list", "cat-file", "pack-objects", "index-pack", "fsck"}
        self.assertFalse(
            any(
                forbidden.intersection(command) or "checkout" in command
                for command in commands
            )
        )

    def test_materializer_accepts_source_pack_without_bitmap_cache(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        git(self.repo, "repack", "-a", "-d", "--no-write-bitmap-index")
        source_pack = self.repo / ".git" / "objects" / "pack"
        self.assertTrue(tuple(source_pack.glob("*.pack")))
        self.assertEqual(tuple(source_pack.glob("*.bitmap")), ())
        destination = self.root / "packed-source-lane"

        result = materialize_worktree(
            self.repo.resolve(),
            destination,
            base,
            head,
        )

        self.assertEqual(result.head_sha, head)
        self.assertEqual(validate_worktree(destination, base, head).head_sha, head)
        self.assertEqual(
            tuple((destination / ".git" / "objects" / "pack").glob("*.bitmap")),
            (),
        )

    def test_materializer_rejects_bundle_and_bare_suffix_dwim_sources(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")

        bundle_source = self.root / "not-a-bundle-repository"
        bundle_source.mkdir()
        git(
            self.repo,
            "bundle",
            "create",
            str(self.root / f"{bundle_source.name}.bundle"),
            "--all",
        )
        bare_source = self.root / "not-a-bare-repository"
        bare_source.mkdir()
        subprocess.run(
            (
                "git",
                "clone",
                "--bare",
                str(self.repo),
                str(self.root / f"{bare_source.name}.git"),
            ),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        for label, source in (
            ("bundle", bundle_source),
            ("bare", bare_source),
        ):
            with self.subTest(label=label):
                destination = self.root / f"{label}-dwim-lane"
                with self.assertRaisesRegex(
                    NamedLaneGuardError,
                    "source must name an exact Git worktree root",
                ):
                    materialize_worktree(
                        source.resolve(),
                        destination,
                        base,
                        head,
                    )
                self.assertFalse(destination.exists())

        ancestor = self.root / "ancestor-repository"
        ancestor.mkdir()
        subprocess.run(
            ("git", "init", "-b", "master", str(ancestor)),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        redirected_source = ancestor / "redirected-worktree"
        redirected_source.mkdir()
        (redirected_source / ".git").mkdir()
        git(ancestor, "config", "core.worktree", str(redirected_source))
        git(
            self.repo,
            "bundle",
            "create",
            str(ancestor / f"{redirected_source.name}.bundle"),
            "--all",
        )
        redirected_destination = self.root / "redirected-dwim-lane"

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "source must name an exact Git worktree root",
        ):
            materialize_worktree(
                redirected_source.resolve(),
                redirected_destination,
                base,
                head,
            )

        self.assertFalse(redirected_destination.exists())

    def test_materializer_fsck_rejects_a_forged_pack_index(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "head-only.txt").write_text("head only\n", encoding="utf-8")
        head = self.commit("head")
        base_tree = bytes.fromhex(git(self.repo, "rev-parse", f"{base}^{{tree}}"))
        head_tree = bytes.fromhex(git(self.repo, "rev-parse", f"{head}^{{tree}}"))
        git(self.repo, "repack", "-ad")
        indexes = list((self.repo / ".git" / "objects" / "pack").glob("*.idx"))
        self.assertEqual(len(indexes), 1)
        index_path = indexes[0]
        payload = bytearray(index_path.read_bytes())
        self.assertEqual(payload[:4], b"\xfftOc")
        self.assertEqual(int.from_bytes(payload[4:8], "big"), 2)
        object_count = int.from_bytes(payload[8 + 255 * 4 : 8 + 256 * 4], "big")
        oid_table = 8 + 256 * 4
        crc_table = oid_table + object_count * 20
        offset_table = crc_table + object_count * 4

        def object_position(object_id: bytes) -> int:
            return next(
                position
                for position in range(object_count)
                if bytes(
                    payload[oid_table + position * 20 : oid_table + (position + 1) * 20]
                )
                == object_id
            )

        base_position = object_position(base_tree)
        head_position = object_position(head_tree)
        for table in (crc_table, offset_table):
            base_entry = slice(
                table + base_position * 4, table + (base_position + 1) * 4
            )
            head_entry = slice(
                table + head_position * 4, table + (head_position + 1) * 4
            )
            base_value = bytes(payload[base_entry])
            payload[base_entry] = payload[head_entry]
            payload[head_entry] = base_value
        payload[-20:] = hashlib.sha1(payload[:-20]).digest()
        index_path.chmod(0o600)
        index_path.write_bytes(payload)
        verification = subprocess.run(
            ("git", "verify-pack", str(index_path)),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(verification.returncode, 0)

        destination = self.root / "forged-pack-index-lane"
        with self.assertRaisesRegex(
            NamedLaneGuardError,
            r"bounded materializer Git (?:ls-tree|fsck) failed",
        ):
            materialize_worktree(
                self.repo.resolve(),
                destination,
                base,
                head,
            )

        self.assertFalse(destination.exists())

    def test_materializer_cwd_is_fenced_from_an_ancestor_repository(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        parent = self.repo / "private-lanes"
        parent.mkdir(mode=0o700)
        destination = parent / "lane"
        original_capture = named_lane_runtime.run_bounded_capture
        observed_fenced_cwd = False

        def probe_init_cwd(argv: object, **kwargs: object) -> object:
            nonlocal observed_fenced_cwd
            command = tuple(argv)
            if not observed_fenced_cwd and "init" in command:
                probe = original_capture(
                    (
                        str(named_lane_runtime.resolve_git()),
                        "rev-parse",
                        "--show-toplevel",
                    ),
                    cwd=kwargs["cwd"],
                    env=kwargs["env"],
                    timeout_seconds=30.0,
                    stdout_limit_bytes=4096,
                    stderr_limit_bytes=4096,
                )
                try:
                    self.assertNotEqual(probe.returncode, 0)
                    self.assertEqual(bytes(probe.stdout), b"")
                finally:
                    probe.stdout[:] = b"\x00" * len(probe.stdout)
                    probe.stderr[:] = b"\x00" * len(probe.stderr)
                observed_fenced_cwd = True
            return original_capture(command, **kwargs)

        with mock.patch.object(
            named_lane_runtime,
            "run_bounded_capture",
            side_effect=probe_init_cwd,
        ):
            materialize_worktree(
                self.repo.resolve(),
                destination,
                base,
                head,
            )

        self.assertTrue(observed_fenced_cwd)
        self.assertEqual(validate_worktree(destination, base, head).head_sha, head)

    def test_materializer_rejects_a_parent_that_cannot_encode_the_ceiling(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        head = self.commit("base")
        parent = self.root / f"ceiling{os.pathsep}parent"
        parent.mkdir(mode=0o700)

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "cannot be encoded as a Git discovery ceiling",
        ):
            materialize_worktree(
                self.repo.resolve(),
                parent / "lane",
                head,
                head,
            )

        self.assertEqual(list(parent.iterdir()), [])

    def test_materializer_does_not_fall_back_to_an_ancestor_repository(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        tracked = self.repo / "tracked.txt"
        tracked.write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        parent = self.repo / "private-fallback-lanes"
        parent.mkdir(mode=0o700)
        destination = parent / "lane"
        original_capture = named_lane_runtime.run_bounded_capture
        removed_target_head = False

        def remove_target_head(argv: object, **kwargs: object) -> object:
            nonlocal removed_target_head
            command = tuple(argv)
            result = original_capture(command, **kwargs)
            if not removed_target_head and "init" in command:
                (destination / ".git" / "HEAD").unlink()
                removed_target_head = True
            return result

        with mock.patch.object(
            named_lane_runtime,
            "run_bounded_capture",
            side_effect=remove_target_head,
        ):
            with self.assertRaisesRegex(
                NamedLaneGuardError,
                r"bounded materializer Git (?:fsck|rev-parse) failed",
            ):
                materialize_worktree(
                    self.repo.resolve(),
                    destination,
                    base,
                    head,
                )

        self.assertTrue(removed_target_head)
        self.assertFalse(destination.exists())
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), head)
        self.assertEqual(tracked.read_text(encoding="utf-8"), "head\n")
        reference = subprocess.run(
            (
                "git",
                "-C",
                str(self.repo),
                "show-ref",
                "--verify",
                "--quiet",
                MATERIALIZER_HEAD_REF,
            ),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(reference.returncode, 0)

    def test_materializer_then_validator_runs_the_first_native_status(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        destination = self.root / "native-trace-lane"
        trace = self.root / "native-git-trace.jsonl"
        real_git = named_lane_runtime.resolve_git()
        traced_git = self.make_executable(
            "import json\n"
            "import os\n"
            "import sys\n"
            f"trace = {str(trace)!r}\n"
            "with open(trace, 'a', encoding='utf-8') as handle:\n"
            "    handle.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            f"os.execv({str(real_git)!r}, [{str(real_git)!r}, *sys.argv[1:]])\n"
        )

        with mock.patch.object(
            named_lane_runtime,
            "resolve_git",
            return_value=traced_git,
        ):
            materialize_worktree(
                self.repo.resolve(),
                destination,
                base,
                head,
            )
            materializer_commands = tuple(
                json.loads(line)
                for line in trace.read_text(encoding="utf-8").splitlines()
            )
            validate_worktree(destination, base, head)
            all_commands = tuple(
                json.loads(line)
                for line in trace.read_text(encoding="utf-8").splitlines()
            )

        status_commands = {"status", "diff-files", "diff-index"}
        self.assertFalse(
            any(
                status_commands.intersection(command)
                for command in materializer_commands
            )
        )
        validator_commands = all_commands[len(materializer_commands) :]
        for command in validator_commands:
            commit_graph_index = command.index("core.commitGraph=false")
            self.assertEqual(command[commit_graph_index - 1], "-c")
            check_stat_index = command.index("core.checkStat=default")
            self.assertEqual(command[check_stat_index - 1], "-c")
            ignore_stat_index = command.index("core.ignoreStat=false")
            self.assertEqual(command[ignore_stat_index - 1], "-c")
            multi_pack_index = command.index("core.multiPackIndex=false")
            self.assertEqual(command[multi_pack_index - 1], "-c")
            trust_ctime_index = command.index("core.trustCtime=true")
            self.assertEqual(command[trust_ctime_index - 1], "-c")
        first_status_index = next(
            index
            for index, command in enumerate(validator_commands)
            if status_commands.intersection(command)
        )
        self.assertIn("status", validator_commands[first_status_index])
        pre_status_commands = validator_commands[:first_status_index]
        self.assertTrue(
            any(
                "show-ref" in command and MATERIALIZER_BASE_REF in command
                for command in pre_status_commands
            )
        )
        self.assertTrue(
            any(
                "show-ref" in command and MATERIALIZER_HEAD_REF in command
                for command in pre_status_commands
            )
        )
        self.assertTrue(any("merge-base" in command for command in pre_status_commands))
        missing_error_traversals = [
            command
            for command in pre_status_commands
            if "rev-list" in command and "--missing=error" in command
        ]
        self.assertGreaterEqual(len(missing_error_traversals), 2)

    def test_validator_formal_gate_rejects_shallow_boundary_drift_before_status(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")

        for label, mutate in (
            ("missing", lambda shallow: shallow.unlink()),
            (
                "changed",
                lambda shallow: shallow.write_bytes(f"{head}\n".encode("ascii")),
            ),
            (
                "additional",
                lambda shallow: shallow.write_bytes(
                    f"{base}\n{head}\n".encode("ascii")
                ),
            ),
        ):
            with self.subTest(label=label):
                destination = self.root / f"formal-shallow-{label}"
                materialize_worktree(self.repo.resolve(), destination, base, head)
                shallow = destination / ".git" / "shallow"
                mutate(shallow)
                if shallow.exists():
                    shallow.chmod(0o600)
                original_capture = named_lane_runtime._git_capture
                commands: list[tuple[str, ...]] = []

                def record_capture(
                    root: pathlib.Path,
                    arguments: object,
                    **kwargs: object,
                ) -> bytes:
                    commands.append(tuple(arguments))
                    return original_capture(root, arguments, **kwargs)

                with mock.patch.object(
                    named_lane_runtime,
                    "_git_capture",
                    side_effect=record_capture,
                ):
                    with self.assertRaises(NamedLaneGuardError):
                        validate_worktree(destination, base, head)

                self.assertFalse(
                    any(
                        {"status", "diff-files", "diff-index"}.intersection(command)
                        for command in commands
                    )
                )

    def test_validator_formal_gate_rejects_frozen_ref_drift(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")

        for label, ref_name, replacement in (
            ("base", MATERIALIZER_BASE_REF, head),
            ("head", MATERIALIZER_HEAD_REF, base),
        ):
            with self.subTest(ref=label):
                destination = self.root / f"formal-ref-{label}"
                materialize_worktree(self.repo.resolve(), destination, base, head)
                git(destination, "update-ref", ref_name, replacement)

                with self.assertRaisesRegex(
                    NamedLaneGuardError,
                    re.escape(ref_name),
                ):
                    validate_worktree(destination, base, head)

    def test_validator_formal_gate_rejects_out_of_range_side_parent(self) -> None:
        (self.repo / "AGENTS.md").write_text("pre-base\n", encoding="utf-8")
        pre_base = self.commit("pre-base")
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "selected.txt").write_text("selected\n", encoding="utf-8")
        selected_parent = self.commit("selected parent")
        selected_tree = git(self.repo, "rev-parse", f"{selected_parent}^{{tree}}")
        head = git(
            self.repo,
            "commit-tree",
            selected_tree,
            "-p",
            selected_parent,
            "-p",
            pre_base,
            "-m",
            "selected merge",
        )
        git(self.repo, "update-ref", "refs/heads/master", head, selected_parent)
        self.bind_formal_validator_range(base, head)

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "shallow commit scope does not match the frozen range",
        ):
            validate_worktree(self.repo.resolve(), base, head)

    @retired_public_commands("validate-worktree")
    def test_validate_worktree_cli_requires_base_and_receipts_frozen_range(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        destination = self.root / "formal-cli-range"
        materialized = materialize_worktree(
            self.repo.resolve(),
            destination,
            base,
            head,
        )

        missing_base_stderr = io.StringIO()
        with (
            contextlib.redirect_stderr(missing_base_stderr),
            self.assertRaises(SystemExit) as missing_base,
        ):
            self.named_lane_main(
                (
                    "validate-worktree",
                    "--worktree",
                    str(destination),
                    "--head",
                    head,
                )
            )
        self.assertEqual(missing_base.exception.code, 2)
        self.assertIn("--base", missing_base_stderr.getvalue())

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            returncode = self.named_lane_main(
                (
                    "validate-worktree",
                    "--worktree",
                    str(destination),
                    "--base",
                    base,
                    "--head",
                    head,
                )
            )

        self.assertEqual(returncode, 0)
        receipt = json.loads(stdout.getvalue())
        self.assertEqual(
            receipt,
            {
                "status": "ok",
                "worktree": str(destination),
                "base": base,
                "head": head,
                "commit_count": 2,
                "parent_edge_count": 1,
                "parent_graph_sha256": materialized.parent_graph_sha256,
                "local_config_sha256": materialized.local_config_sha256,
                "symlink_count": 0,
                "guidance_count": 1,
            },
        )

    def test_validator_fences_a_nonrepository_from_its_ancestor(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit("ancestor")
        nested = self.repo / "not-a-worktree"
        nested.mkdir(mode=0o700)
        with (
            mock.patch.object(
                named_lane_runtime,
                "_git_capture",
                wraps=named_lane_runtime._git_capture,
            ) as capture,
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "does not have a private Git directory",
            ),
        ):
            validate_worktree(nested.resolve(), head, head)

        capture.assert_not_called()

    def test_validator_rejects_any_config_worktree_before_repository_query(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        head = self.commit("base")
        destination = self.root / "config-worktree-lane"
        materialize_worktree(self.repo.resolve(), destination, head, head)
        (destination / ".git" / "config.worktree").write_text(
            "[core]\n\tfsmonitor = false\n",
            encoding="utf-8",
        )

        with (
            mock.patch.object(
                named_lane_runtime,
                "_git_capture",
                wraps=named_lane_runtime._git_capture,
            ) as capture,
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "per-worktree Git config is not allowed",
            ),
        ):
            validate_worktree(destination, head, head)

        capture.assert_not_called()

    def test_validator_rejects_direct_stat_weakening_before_repository_query(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        head = self.commit("base")
        for index, (key, value) in enumerate(
            (
                ("core.checkStat", "minimal"),
                ("core.trustCtime", "false"),
                ("core.ignoreStat", "true"),
            )
        ):
            with self.subTest(key=key):
                destination = self.root / f"unsafe-stat-{index}"
                materialize_worktree(self.repo.resolve(), destination, head, head)
                git(destination, "config", key, value)
                with (
                    mock.patch.object(
                        named_lane_runtime,
                        "_git_capture",
                        wraps=named_lane_runtime._git_capture,
                    ) as capture,
                    self.assertRaisesRegex(
                        NamedLaneGuardError,
                        "direct core.checkStat, core.trustCtime, and core.ignoreStat",
                    ),
                ):
                    validate_worktree(destination, head, head)
                capture.assert_not_called()

    def test_validator_rejects_target_graft_before_topology_query(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        head = self.commit("base")
        destination = self.root / "grafted-lane"
        materialize_worktree(self.repo.resolve(), destination, head, head)
        (destination / ".git" / "info" / "grafts").write_text(
            f"{head}\n",
            encoding="ascii",
        )

        with (
            mock.patch.object(
                named_lane_runtime,
                "_git_capture",
                wraps=named_lane_runtime._git_capture,
            ) as capture,
            self.assertRaisesRegex(NamedLaneGuardError, "graft state is not allowed"),
        ):
            validate_worktree(destination, head, head)

        capture.assert_not_called()

    def test_materializer_rejects_graft_injected_before_topology_import(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        head = self.commit("base")
        destination = self.root / "materializer-graft-lane"
        original_capture = named_lane_runtime.run_bounded_capture
        injected = False
        commands_after_injection: list[tuple[str, ...]] = []

        def inject_graft(argv: object, **kwargs: object) -> object:
            nonlocal injected
            command = tuple(str(item) for item in argv)
            result = original_capture(command, **kwargs)
            if injected:
                commands_after_injection.append(command)
            elif (
                destination.exists()
                and (destination / ".git" / "info").is_dir()
                and "config" in command
                and "--file" in command
                and "-" in command
                and "--list" in command
            ):
                (destination / ".git" / "info" / "grafts").write_text(
                    f"{head}\n",
                    encoding="ascii",
                )
                injected = True
            return result

        with (
            mock.patch.object(
                named_lane_runtime,
                "run_bounded_capture",
                side_effect=inject_graft,
            ),
            self.assertRaisesRegex(NamedLaneGuardError, "graft state is not allowed"),
        ):
            materialize_worktree(self.repo.resolve(), destination, head, head)

        self.assertTrue(injected)
        self.assertFalse(destination.exists())
        for command in commands_after_injection:
            self.assertTrue(
                {"rev-list", "merge-base", "pack-objects"}.isdisjoint(command)
            )

    def test_validator_rejects_non_private_git_info_mode(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        head = self.commit("base")
        destination = self.root / "info-mode-lane"
        materialize_worktree(self.repo.resolve(), destination, head, head)
        (destination / ".git" / "info").chmod(0o755)

        with (
            mock.patch.object(
                named_lane_runtime,
                "_git_capture",
                wraps=named_lane_runtime._git_capture,
            ) as capture,
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "info directory must be an owner-private real directory",
            ),
        ):
            validate_worktree(destination, head, head)

        capture.assert_not_called()

    def test_status_detects_same_size_tracked_content_with_restored_mtime(
        self,
    ) -> None:
        tracked = self.repo / "tracked.txt"
        tracked.write_text("AAAA\n", encoding="ascii")
        head = self.commit("base")
        before = tracked.stat()
        tracked.write_text("BBBB\n", encoding="ascii")
        os.utime(tracked, ns=(before.st_atime_ns, before.st_mtime_ns))
        after = tracked.stat()
        self.assertEqual(after.st_size, before.st_size)
        self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)

        with self.assertRaisesRegex(NamedLaneGuardError, "worktree must be clean"):
            self.validate_repo(head)

    def test_validator_rejects_same_length_config_replacement_with_old_mtime(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        head = self.commit("base")
        destination = self.root / "config-replacement-lane"
        materialize_worktree(self.repo.resolve(), destination, head, head)
        config = destination / ".git" / "config"
        original_validate = named_lane_runtime._validate_guidance_file
        replaced = False

        def replace_config(*args: object, **kwargs: object) -> None:
            nonlocal replaced
            original_validate(*args, **kwargs)
            if replaced:
                return
            before = config.stat()
            original = config.read_bytes()
            replacement = config.with_name("config.same-length-replacement")
            replacement.write_bytes(original)
            replacement.chmod(stat.S_IMODE(before.st_mode))
            os.utime(
                replacement,
                ns=(before.st_atime_ns, before.st_mtime_ns),
            )
            os.replace(replacement, config)
            self.assertEqual(config.stat().st_size, before.st_size)
            self.assertEqual(config.stat().st_mtime_ns, before.st_mtime_ns)
            replaced = True

        with (
            mock.patch.object(
                named_lane_runtime,
                "_validate_guidance_file",
                side_effect=replace_config,
            ),
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "local Git config identity changed during the protected window",
            ),
        ):
            validate_worktree(destination, head, head)

        self.assertTrue(replaced)

    def test_validator_allows_config_timestamp_churn_without_property_change(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        head = self.commit("base")
        destination = self.root / "config-timestamp-lane"
        materialized = materialize_worktree(
            self.repo.resolve(),
            destination,
            head,
            head,
        )
        config = destination / ".git" / "config"
        original_validate = named_lane_runtime._validate_guidance_file
        touched = False

        def touch_config(*args: object, **kwargs: object) -> None:
            nonlocal touched
            original_validate(*args, **kwargs)
            if not touched:
                metadata = config.stat()
                os.utime(
                    config,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000),
                )
                touched = True

        with mock.patch.object(
            named_lane_runtime,
            "_validate_guidance_file",
            side_effect=touch_config,
        ):
            validated = validate_worktree(destination, head, head)

        self.assertTrue(touched)
        self.assertEqual(
            validated.local_config_sha256,
            materialized.local_config_sha256,
        )

    def test_receipts_bind_config_content_across_guard_invocations(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        head = self.commit("base")
        destination = self.root / "config-receipt-lane"
        materialized = materialize_worktree(
            self.repo.resolve(),
            destination,
            head,
            head,
        )
        config = destination / ".git" / "config"
        original = config.read_bytes()
        original_mode = stat.S_IMODE(config.stat().st_mode)
        replacement = config.with_name("config.same-content-replacement")
        replacement.write_bytes(original)
        replacement.chmod(original_mode)
        os.replace(replacement, config)

        same_content = validate_worktree(destination, head, head)
        self.assertEqual(
            same_content.local_config_sha256,
            materialized.local_config_sha256,
        )

        with config.open("ab") as handle:
            handle.write(b"\n# receipt drift\n")
        changed_content = validate_worktree(destination, head, head)
        self.assertEqual(
            changed_content.parent_graph_sha256,
            materialized.parent_graph_sha256,
        )
        self.assertNotEqual(
            changed_content.local_config_sha256,
            materialized.local_config_sha256,
        )

    def test_validator_rejects_git_info_identity_drift_after_guidance(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        head = self.commit("base")
        destination = self.root / "info-replacement-lane"
        materialize_worktree(self.repo.resolve(), destination, head, head)
        info = destination / ".git" / "info"
        original_info = destination / ".git" / "info.original"
        original_validate = named_lane_runtime._validate_guidance_file
        replaced = False

        def replace_info(*args: object, **kwargs: object) -> None:
            nonlocal replaced
            original_validate(*args, **kwargs)
            if replaced:
                return
            info.rename(original_info)
            info.mkdir(mode=0o700)
            info.chmod(0o700)
            replaced = True

        with (
            mock.patch.object(
                named_lane_runtime,
                "_validate_guidance_file",
                side_effect=replace_info,
            ),
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "Git info directory identity changed during the protected window",
            ),
        ):
            validate_worktree(destination, head, head)

        self.assertTrue(replaced)

    @retired_public_commands("validate-worktree")
    def test_validator_reports_distinct_local_config_failures(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        head = self.commit("base")
        cases = (
            ("missing", "materialized-git-config-missing"),
            ("unreadable", "materialized-git-config-inspection-failure"),
            ("identity", "materialized-git-config-object-identity-mismatch"),
            ("content", "materialized-git-config-content-mismatch"),
            ("access-policy", "materialized-git-config-access-policy-mismatch"),
        )

        for case, expected_reason in cases:
            with self.subTest(case=case):
                destination = self.root / f"config-reason-{case}"
                materialize_worktree(self.repo.resolve(), destination, head, head)
                config = destination / ".git" / "config"
                original_validate = named_lane_runtime._validate_guidance_file
                original_open = os.open
                injected = False

                def inject_failure(*args: object, **kwargs: object) -> None:
                    nonlocal injected
                    original_validate(*args, **kwargs)
                    if injected:
                        return
                    injected = True
                    if case == "missing":
                        config.unlink()
                    elif case == "identity":
                        metadata = config.stat()
                        replacement = config.with_name("config.identity-replacement")
                        replacement.write_bytes(config.read_bytes())
                        replacement.chmod(stat.S_IMODE(metadata.st_mode))
                        os.replace(replacement, config)
                    elif case == "content":
                        with config.open("r+b") as handle:
                            original = handle.read(1)
                            self.assertTrue(original)
                            handle.seek(0)
                            handle.write(bytes((original[0] ^ 1,)))
                    elif case == "access-policy":
                        original_mode = stat.S_IMODE(config.stat().st_mode)
                        config.chmod(original_mode ^ stat.S_IRGRP)

                def deny_read(path: object, *args: object, **kwargs: object) -> int:
                    if (
                        case == "unreadable"
                        and injected
                        and os.fspath(path) == os.fspath(config)
                    ):
                        raise PermissionError("synthetic config read denial")
                    return original_open(path, *args, **kwargs)

                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    mock.patch.object(
                        named_lane_runtime,
                        "_validate_guidance_file",
                        side_effect=inject_failure,
                    ),
                    mock.patch.object(
                        named_lane_runtime.os, "open", side_effect=deny_read
                    ),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    returncode = self.named_lane_main(
                        (
                            "validate-worktree",
                            "--worktree",
                            str(destination),
                            "--base",
                            head,
                            "--head",
                            head,
                        )
                    )

                self.assertTrue(injected)
                self.assertEqual(returncode, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(
                    json.loads(stderr.getvalue()),
                    {"status": "blocked-safety", "reason": expected_reason},
                )

    @retired_public_commands("validate-worktree")
    def test_validator_reports_config_input_inspection_failures(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        head = self.commit("base")
        cases = (
            ("malformed", b'[core "broken"\n'),
            (
                "oversized",
                b"#"
                * (named_lane_runtime.MATERIALIZER_SOURCE_CONTROL_FILE_LIMIT_BYTES + 1),
            ),
        )

        for case, config_payload in cases:
            with self.subTest(case=case):
                destination = self.root / f"config-input-reason-{case}"
                materialize_worktree(self.repo.resolve(), destination, head, head)
                (destination / ".git" / "config").write_bytes(config_payload)
                stdout = io.StringIO()
                stderr = io.StringIO()

                with (
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    returncode = self.named_lane_main(
                        (
                            "validate-worktree",
                            "--worktree",
                            str(destination),
                            "--base",
                            head,
                            "--head",
                            head,
                        )
                    )

                self.assertEqual(returncode, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(
                    json.loads(stderr.getvalue()),
                    {
                        "status": "blocked-safety",
                        "reason": "materialized-git-config-inspection-failure",
                    },
                )

    @retired_public_commands("validate-worktree")
    def test_validator_reports_config_record_inspection_failure(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        head = self.commit("base")
        destination = self.root / "config-record-reason"
        materialize_worktree(self.repo.resolve(), destination, head, head)
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            mock.patch.object(
                named_lane_runtime,
                "_parse_git_config_records",
                side_effect=NamedLaneGuardError("synthetic malformed record"),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                (
                    "validate-worktree",
                    "--worktree",
                    str(destination),
                    "--base",
                    head,
                    "--head",
                    head,
                )
            )

        self.assertEqual(returncode, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {
                "status": "blocked-safety",
                "reason": "materialized-git-config-inspection-failure",
            },
        )

    @retired_public_commands("validate-worktree")
    def test_validator_reports_distinct_git_info_failures(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        head = self.commit("base")
        cases = (
            ("missing", "materialized-git-info-missing"),
            ("unreadable", "materialized-git-info-inspection-failure"),
            ("identity", "materialized-git-info-object-identity-mismatch"),
            ("content", "materialized-git-info-content-mismatch"),
            ("access-policy", "materialized-git-info-access-policy-mismatch"),
        )

        for case, expected_reason in cases:
            with self.subTest(case=case):
                destination = self.root / f"info-reason-{case}"
                materialize_worktree(self.repo.resolve(), destination, head, head)
                info = destination / ".git" / "info"
                retained_info = destination / ".git" / f"info.retained-{case}"
                original_validate = named_lane_runtime._validate_guidance_file
                original_open = os.open
                injected = False

                def inject_failure(*args: object, **kwargs: object) -> None:
                    nonlocal injected
                    original_validate(*args, **kwargs)
                    if injected:
                        return
                    injected = True
                    if case == "missing":
                        info.rename(retained_info)
                    elif case == "identity":
                        info.rename(retained_info)
                        info.mkdir(mode=0o700)
                        info.chmod(0o700)
                    elif case == "content":
                        (info / "grafts").write_text(f"{head}\n", encoding="ascii")
                    elif case == "access-policy":
                        info.chmod(0o755)

                def deny_read(path: object, *args: object, **kwargs: object) -> int:
                    if (
                        case == "unreadable"
                        and injected
                        and os.fspath(path) == os.fspath(info)
                    ):
                        raise PermissionError("synthetic info read denial")
                    return original_open(path, *args, **kwargs)

                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    mock.patch.object(
                        named_lane_runtime,
                        "_validate_guidance_file",
                        side_effect=inject_failure,
                    ),
                    mock.patch.object(
                        named_lane_runtime.os, "open", side_effect=deny_read
                    ),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    returncode = self.named_lane_main(
                        (
                            "validate-worktree",
                            "--worktree",
                            str(destination),
                            "--base",
                            head,
                            "--head",
                            head,
                        )
                    )

                self.assertTrue(injected)
                self.assertEqual(returncode, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(
                    json.loads(stderr.getvalue()),
                    {"status": "blocked-safety", "reason": expected_reason},
                )

    def test_materializer_requires_git_245_or_newer(self) -> None:
        environment = named_lane_runtime._git_environment()
        for version, expected_error in (
            ("2.35.1", "requires Git 2.45.0 or newer"),
            ("2.44.9", "requires Git 2.45.0 or newer"),
            ("2.45.0.rc1", "version could not be validated"),
            ("2.45.0", None),
            ("2.53.0 (Apple Git-154.1)", None),
        ):
            with self.subTest(version=version):
                candidate = self.make_executable(f"print('git version {version}')\n")
                if expected_error is None:
                    _validate_materializer_git_version(
                        candidate,
                        environment,
                        self.root,
                    )
                else:
                    with self.assertRaisesRegex(
                        NamedLaneGuardError,
                        expected_error,
                    ):
                        _validate_materializer_git_version(
                            candidate,
                            environment,
                            self.root,
                        )

    def test_materializer_neutralizes_ambient_and_source_execution_surfaces(
        self,
    ) -> None:
        marker = self.root / "unexpected-execution.marker"
        probe = self.make_executable(
            f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
        )
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / ".gitattributes").write_text(
            "tracked.txt filter=unsafe\n",
            encoding="utf-8",
        )
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        source_hooks = self.repo / ".git" / "hooks"
        shutil.copy2(probe, source_hooks / "post-checkout")
        shutil.copy2(probe, source_hooks / "reference-transaction")
        git(self.repo, "config", "core.hooksPath", str(source_hooks))
        git(self.repo, "config", "core.fsmonitor", str(probe))
        git(self.repo, "config", "filter.unsafe.smudge", str(probe))
        git(self.repo, "config", "filter.unsafe.process", str(probe))

        ambient_home = self.root / "ambient-home"
        ambient_home.mkdir()
        ambient_template = self.root / "ambient-template"
        (ambient_template / "hooks").mkdir(parents=True)
        shutil.copy2(probe, ambient_template / "hooks" / "post-checkout")
        shutil.copy2(
            probe,
            ambient_template / "hooks" / "reference-transaction",
        )
        ambient_global = self.root / "ambient-global.config"
        ambient_global.write_text(
            "[core]\n"
            f"\thooksPath = {ambient_template / 'hooks'}\n"
            f"\tfsmonitor = {probe}\n"
            '[filter "unsafe"]\n'
            f"\tprocess = {probe}\n"
            "[init]\n"
            f"\ttemplateDir = {ambient_template}\n"
            "[submodule]\n"
            "\trecurse = true\n",
            encoding="utf-8",
        )
        ambient_system = self.root / "ambient-system.config"
        ambient_system.write_text(
            f'[filter "unsafe"]\n\tsmudge = {probe}\n',
            encoding="utf-8",
        )
        destination = self.root / "ambient-safe-lane"
        previous_cwd = pathlib.Path.cwd()
        try:
            os.chdir(self.repo)
            with mock.patch.dict(
                os.environ,
                {
                    "HOME": str(ambient_home),
                    "XDG_CONFIG_HOME": str(ambient_home / "xdg"),
                    "GIT_CONFIG_GLOBAL": str(ambient_global),
                    "GIT_CONFIG_NOSYSTEM": "0",
                    "GIT_CONFIG_SYSTEM": str(ambient_system),
                },
            ):
                result = materialize_worktree(
                    self.repo.resolve(),
                    destination,
                    base,
                    head,
                )
        finally:
            os.chdir(previous_cwd)

        self.assertEqual(result.head_sha, head)
        self.assertFalse(marker.exists())
        self.assertEqual(validate_worktree(destination, base, head).head_sha, head)

    def test_materializer_private_hooks_override_injected_target_hook(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        destination = self.root / "target-hook-lane"
        marker = self.root / "target-hook.marker"
        probe = self.make_executable(
            f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
        )
        original_capture = named_lane_runtime.run_bounded_capture
        injected = False

        def inject_hook(argv: object, **kwargs: object) -> object:
            nonlocal injected
            result = original_capture(argv, **kwargs)
            if not injected and "init" in tuple(argv):
                target_hooks = destination / ".git" / "hooks"
                target_hooks.mkdir(exist_ok=True)
                shutil.copy2(probe, target_hooks / "post-checkout")
                shutil.copy2(probe, target_hooks / "reference-transaction")
                injected = True
            return result

        with mock.patch.object(
            named_lane_runtime,
            "run_bounded_capture",
            side_effect=inject_hook,
        ):
            result = materialize_worktree(
                self.repo.resolve(),
                destination,
                base,
                head,
            )

        self.assertTrue(injected)
        self.assertEqual(result.head_sha, head)
        self.assertFalse(marker.exists())
        self.assertEqual(validate_worktree(destination, base, head).head_sha, head)

    def test_materializer_accepts_a_linked_source_worktree(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        linked_source = self.root / "linked-source"
        git(
            self.repo,
            "worktree",
            "add",
            "--detach",
            str(linked_source),
            head,
        )
        destination = self.root / "linked-source-lane"

        result = materialize_worktree(
            linked_source.resolve(),
            destination,
            base,
            head,
        )

        self.assertEqual(result.head_sha, head)
        self.assertEqual(validate_worktree(destination, base, head).head_sha, head)
        self.assertFalse(
            (destination / ".git" / "objects" / "info" / "alternates").exists()
        )

    def test_materializer_accepts_linked_source_marker_metadata_churn(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        head = base
        linked_source = self.root / "linked-marker-metadata-source"
        git(self.repo, "worktree", "add", "--detach", str(linked_source), head)
        marker = linked_source / ".git"
        extra_link = self.root / "linked-marker-extra-link"
        destination = self.root / "linked-marker-metadata-lane"
        original_validate = named_lane_runtime._validate_materializer_git_version
        initial_metadata = marker.lstat()
        mutated = False

        def mutate_marker_metadata(*args: object, **kwargs: object) -> object:
            nonlocal mutated
            result = original_validate(*args, **kwargs)
            time.sleep(0.01)
            os.link(marker, extra_link)
            os.utime(
                marker,
                ns=(
                    initial_metadata.st_atime_ns,
                    max(0, initial_metadata.st_mtime_ns - 1_000_000_000),
                ),
            )
            current_metadata = marker.lstat()
            self.assertEqual(current_metadata.st_ino, initial_metadata.st_ino)
            self.assertEqual(current_metadata.st_nlink, initial_metadata.st_nlink + 1)
            self.assertNotEqual(
                current_metadata.st_mtime_ns,
                initial_metadata.st_mtime_ns,
            )
            self.assertNotEqual(
                current_metadata.st_ctime_ns,
                initial_metadata.st_ctime_ns,
            )
            mutated = True
            return result

        try:
            with mock.patch.object(
                named_lane_runtime,
                "_validate_materializer_git_version",
                side_effect=mutate_marker_metadata,
            ):
                result = materialize_worktree(
                    linked_source.resolve(),
                    destination,
                    base,
                    head,
                )
        finally:
            extra_link.unlink(missing_ok=True)

        self.assertTrue(mutated)
        self.assertEqual(result.head_sha, head)
        self.assertEqual(validate_worktree(destination, base, head).head_sha, head)

    def test_materializer_control_file_fifo_swap_fails_without_blocking(self) -> None:
        control = self.root / "materializer-control"
        control.write_text("control\n", encoding="utf-8")
        original_open = os.open
        observed_flags: int | None = None

        def swap_to_fifo(
            path: os.PathLike[str] | str,
            flags: int,
            *args: object,
            **kwargs: object,
        ) -> int:
            nonlocal observed_flags
            if pathlib.Path(path) == control:
                control.unlink()
                os.mkfifo(control)
                observed_flags = flags
                self.assertNotEqual(flags & os.O_NONBLOCK, 0)
            return original_open(path, flags, *args, **kwargs)

        started = time.monotonic()
        with (
            mock.patch.object(
                named_lane_runtime.os,
                "open",
                side_effect=swap_to_fifo,
            ),
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "Git admin back-pointer changed during inspection",
            ),
        ):
            named_lane_runtime._read_materializer_control_file(
                control,
                label="Git admin back-pointer",
            )

        self.assertIsNotNone(observed_flags)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_materializer_rejects_linked_source_marker_type_drift(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        linked_source = self.root / "linked-marker-type-source"
        git(self.repo, "worktree", "add", "--detach", str(linked_source), head)
        marker = linked_source / ".git"
        backup = linked_source / ".git.original"
        destination = self.root / "linked-marker-type-lane"
        original_validate = named_lane_runtime._validate_materializer_git_version
        mutated = False

        def mutate_marker(*args: object, **kwargs: object) -> object:
            nonlocal mutated
            result = original_validate(*args, **kwargs)
            marker.rename(backup)
            marker.mkdir()
            mutated = True
            return result

        try:
            with (
                mock.patch.object(
                    named_lane_runtime,
                    "_validate_materializer_git_version",
                    side_effect=mutate_marker,
                ),
                self.assertRaisesRegex(
                    NamedLaneGuardError,
                    "Git admin marker changed during materialization",
                ),
            ):
                materialize_worktree(
                    linked_source.resolve(),
                    destination,
                    base,
                    head,
                )
        finally:
            if marker.is_dir():
                marker.rmdir()
            if backup.exists():
                backup.rename(marker)

        self.assertTrue(mutated)
        self.assertFalse(destination.exists())

    def test_materializer_rejects_linked_source_marker_identity_drift(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        head = base
        linked_source = self.root / "linked-marker-identity-source"
        git(self.repo, "worktree", "add", "--detach", str(linked_source), head)
        marker = linked_source / ".git"
        original_payload = marker.read_bytes()
        original_inode = marker.stat().st_ino
        destination = self.root / "linked-marker-identity-lane"
        original_validate = named_lane_runtime._validate_materializer_git_version
        mutated = False

        def mutate_marker(*args: object, **kwargs: object) -> object:
            nonlocal mutated
            result = original_validate(*args, **kwargs)
            replacement = linked_source / ".git.replacement"
            replacement.write_bytes(original_payload)
            os.replace(replacement, marker)
            mutated = marker.stat().st_ino != original_inode
            return result

        with (
            mock.patch.object(
                named_lane_runtime,
                "_validate_materializer_git_version",
                side_effect=mutate_marker,
            ),
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "Git admin marker changed during materialization",
            ),
        ):
            materialize_worktree(
                linked_source.resolve(),
                destination,
                base,
                head,
            )

        self.assertTrue(mutated)
        self.assertFalse(destination.exists())

    def test_materializer_rejects_linked_source_marker_target_drift(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        head = base
        first_source = self.root / "linked-marker-target-source"
        second_source = self.root / "linked-marker-other-source"
        git(self.repo, "worktree", "add", "--detach", str(first_source), head)
        git(self.repo, "worktree", "add", "--detach", str(second_source), head)
        marker = first_source / ".git"
        original_payload = marker.read_bytes()
        other_payload = (second_source / ".git").read_bytes()
        original_inode = marker.stat().st_ino
        destination = self.root / "linked-marker-target-lane"
        original_validate = named_lane_runtime._validate_materializer_git_version
        mutated = False

        def mutate_marker(*args: object, **kwargs: object) -> object:
            nonlocal mutated
            result = original_validate(*args, **kwargs)
            marker.write_bytes(other_payload)
            mutated = marker.stat().st_ino == original_inode
            return result

        try:
            with (
                mock.patch.object(
                    named_lane_runtime,
                    "_validate_materializer_git_version",
                    side_effect=mutate_marker,
                ),
                self.assertRaisesRegex(
                    NamedLaneGuardError,
                    "Git admin marker changed during materialization",
                ),
            ):
                materialize_worktree(
                    first_source.resolve(),
                    destination,
                    base,
                    head,
                )
        finally:
            marker.write_bytes(original_payload)

        self.assertTrue(mutated)
        self.assertFalse(destination.exists())

    def test_materializer_rejects_linked_source_back_pointer_drift(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        head = base
        first_source = self.root / "linked-back-pointer-source"
        second_source = self.root / "linked-back-pointer-other-source"
        git(self.repo, "worktree", "add", "--detach", str(first_source), head)
        git(self.repo, "worktree", "add", "--detach", str(second_source), head)
        first_admin = pathlib.Path(git(first_source, "rev-parse", "--absolute-git-dir"))
        back_pointer = first_admin / "gitdir"
        original_payload = back_pointer.read_bytes()
        original_inode = back_pointer.lstat().st_ino
        destination = self.root / "linked-back-pointer-lane"
        original_validate = named_lane_runtime._materializer_validate_checkout_manifest
        mutated = False

        def mutate_back_pointer(*args: object, **kwargs: object) -> object:
            nonlocal mutated
            result = original_validate(*args, **kwargs)
            back_pointer.write_text(
                f"{second_source / '.git'}\n",
                encoding="utf-8",
            )
            mutated = back_pointer.lstat().st_ino == original_inode
            return result

        try:
            with (
                mock.patch.object(
                    named_lane_runtime,
                    "_materializer_validate_checkout_manifest",
                    side_effect=mutate_back_pointer,
                ),
                self.assertRaisesRegex(
                    NamedLaneGuardError,
                    "Git admin directory does not match its exact marker",
                ),
            ):
                materialize_worktree(
                    first_source.resolve(),
                    destination,
                    base,
                    head,
                )
        finally:
            back_pointer.write_bytes(original_payload)

        self.assertTrue(mutated)
        self.assertFalse(destination.exists())

    def test_materializer_rejects_linked_source_per_worktree_shallow_state(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        linked_source = self.root / "linked-shallow-source"
        git(
            self.repo,
            "worktree",
            "add",
            "--detach",
            str(linked_source),
            head,
        )
        linked_admin = pathlib.Path(
            git(linked_source, "rev-parse", "--absolute-git-dir")
        )
        shallow = linked_admin / "shallow"
        destination = self.root / "linked-shallow-lane"
        shallow.write_bytes(b"")
        try:
            with self.assertRaisesRegex(
                NamedLaneGuardError,
                "per-worktree shallow repository state is not allowed",
            ):
                materialize_worktree(
                    linked_source.resolve(),
                    destination,
                    base,
                    head,
                )
        finally:
            shallow.unlink(missing_ok=True)

        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".named-lane-materializer-*")), [])

    def test_materializer_preserves_sha256_object_format(self) -> None:
        sha256_repo = self.root / "sha256-repo"
        sha256_repo.mkdir()
        git(sha256_repo, "init", "-b", "master", "--object-format=sha256")
        git(sha256_repo, "config", "user.name", "Named Lane Test")
        git(
            sha256_repo,
            "config",
            "user.email",
            "named-lane@example.invalid",
        )
        git(sha256_repo, "config", "commit.gpgsign", "false")
        (sha256_repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        git(sha256_repo, "add", "-A")
        git(sha256_repo, "commit", "-m", "base")
        base = git(sha256_repo, "rev-parse", "HEAD")
        (sha256_repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        git(sha256_repo, "add", "-A")
        git(sha256_repo, "commit", "-m", "head")
        head = git(sha256_repo, "rev-parse", "HEAD")
        destination = self.root / "sha256-lane"

        result = materialize_worktree(
            sha256_repo.resolve(),
            destination,
            base,
            head,
        )

        self.assertEqual(len(head), 64)
        self.assertEqual(result.head_sha, head)
        self.assertEqual(
            git(destination, "config", "--local", "extensions.objectFormat"),
            "sha256",
        )
        self.assertEqual(validate_worktree(destination, base, head).head_sha, head)

    def test_materializer_hard_caps_fail_closed_and_clean_destination(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head payload\n", encoding="utf-8")
        head = self.commit("head")
        cases = (
            (
                "source-control-bytes",
                "MATERIALIZER_SOURCE_CONTROL_FILE_LIMIT_BYTES",
                1,
                "exact Git worktree root",
            ),
            (
                "object-count",
                "MATERIALIZER_OBJECT_COUNT_LIMIT",
                1,
                "object-count limit",
            ),
            (
                "logical-bytes",
                "MATERIALIZER_LOGICAL_OBJECT_BYTES_LIMIT",
                1,
                "logical-byte limit",
            ),
            (
                "checkout-entries",
                "MATERIALIZER_CHECKOUT_ENTRY_COUNT_LIMIT",
                1,
                "entry-count limit",
            ),
            (
                "checkout-blobs",
                "MATERIALIZER_CHECKOUT_BLOB_BYTES_LIMIT",
                1,
                "blob-occurrence-byte limit",
            ),
            (
                "checkout-paths",
                "MATERIALIZER_CHECKOUT_PATH_BYTES_LIMIT",
                1,
                "aggregate-path-byte limit",
            ),
            (
                "pack-bytes",
                "MATERIALIZER_PACK_BYTES_LIMIT",
                64,
                "compressed-byte limit",
            ),
        )

        for label, constant, limit, expected in cases:
            with self.subTest(label=label):
                destination = self.root / f"capped-{label}-lane"
                with (
                    mock.patch.object(named_lane_runtime, constant, limit),
                    self.assertRaisesRegex(NamedLaneGuardError, expected),
                ):
                    materialize_worktree(
                        self.repo.resolve(),
                        destination,
                        base,
                        head,
                    )

                self.assertFalse(destination.exists())
                self.assertEqual(
                    list(self.root.glob(".named-lane-materializer-*")),
                    [],
                )

    def test_materializer_rejects_source_promisor_configuration(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        head = self.commit("base")
        config = self.repo / ".git" / "config"
        original_config = config.read_bytes()
        cases = (
            ("partial-clone", b"[extensions]\n\tpartialClone = origin\n"),
            ("promisor-remote", b'[remote "origin"]\n\tpromisor = true\n'),
        )

        for label, addition in cases:
            with self.subTest(label=label):
                config.write_bytes(original_config + addition)
                destination = self.root / f"source-{label}-lane"
                try:
                    with self.assertRaisesRegex(
                        NamedLaneGuardError,
                        "source Git promisor configuration is not allowed",
                    ):
                        materialize_worktree(
                            self.repo.resolve(),
                            destination,
                            head,
                            head,
                        )
                finally:
                    config.write_bytes(original_config)

                self.assertFalse(destination.exists())

    def test_materializer_rejects_source_alternates_shallow_and_promisor_state(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        head = self.commit("base")
        objects = self.repo / ".git" / "objects"
        info = objects / "info"
        pack = objects / "pack"
        info.mkdir(exist_ok=True)
        pack.mkdir(exist_ok=True)
        cases = (
            (info / "alternates", b"", "alternates is not allowed"),
            (
                info / "http-alternates",
                b"",
                "HTTP alternates is not allowed",
            ),
            (self.repo / ".git" / "shallow", b"", "shallow repository state"),
            (pack / "source.promisor", b"", "promisor state is not allowed"),
            (pack / "source.BiTmAp", b"", "bitmap cache is not allowed"),
        )

        for index, (state_path, payload, expected) in enumerate(cases):
            with self.subTest(path=state_path.name):
                state_path.write_bytes(payload)
                destination = self.root / f"source-state-{index}-lane"
                try:
                    with self.assertRaisesRegex(NamedLaneGuardError, expected):
                        materialize_worktree(
                            self.repo.resolve(),
                            destination,
                            head,
                            head,
                        )
                finally:
                    state_path.unlink(missing_ok=True)

                self.assertFalse(destination.exists())

    def test_materializer_rejects_unsafe_target_config_before_checkout(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        marker = self.root / "unsafe-target.marker"
        probe = self.make_executable(
            f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
        )
        included = self.root / "unsafe-included.config"
        included.write_text(
            f'[filter "unsafe"]\n\tprocess = {probe}\n',
            encoding="utf-8",
        )
        cases = (
            ("include", "include.path", str(included), "include directives"),
            (
                "include-if",
                "includeIf.gitdir:/never/.path",
                str(included),
                "include directives",
            ),
            ("alias", "alias.review", f"!{probe}", "aliases"),
            ("credential", "credential.helper", str(probe), "credential configuration"),
            ("fsck", "fsck.skipList", os.devnull, "fsck policy"),
            ("fsmonitor", "core.fsmonitor", str(probe), "fsmonitor"),
            ("fsmonitor-no-value", "core.fsmonitor", None, "fsmonitor"),
            (
                "hooks",
                "core.hooksPath",
                str(self.root / "unsafe-hooks"),
                "hooksPath",
            ),
            ("clean", "filter.unsafe.clean", str(probe), "filter or diff"),
            ("smudge", "filter.unsafe.smudge", str(probe), "filter or diff"),
            ("process", "filter.unsafe.process", str(probe), "filter or diff"),
            ("diff-external", "diff.external", str(probe), "filter or diff"),
            ("diff-command", "diff.unsafe.command", str(probe), "filter or diff"),
            ("diff", "diff.unsafe.textconv", str(probe), "filter or diff"),
            (
                "extension",
                "extensions.worktreeConfig",
                "true",
                "repository extension",
            ),
            ("sparse", "core.sparseCheckout", "true", "sparse checkout"),
            ("submodule", "submodule.recurse", "true", "recursion"),
            ("submodule-no-value", "submodule.recurse", None, "recursion"),
            (
                "remote-command",
                "remote.origin.uploadpack",
                str(probe),
                "remote configuration",
            ),
        )
        original_capture = named_lane_runtime.run_bounded_capture

        for label, key, value, expected in cases:
            with self.subTest(label=label):
                destination = self.root / f"unsafe-{label}-lane"
                commands: list[tuple[str, ...]] = []
                injected = False

                def inject_config(argv: object, **kwargs: object) -> object:
                    nonlocal injected
                    command = tuple(argv)
                    commands.append(command)
                    result = original_capture(command, **kwargs)
                    if not injected and "init" in command:
                        if value is None:
                            section, name = key.split(".", 1)
                            with (destination / ".git" / "config").open(
                                "a",
                                encoding="utf-8",
                            ) as handle:
                                handle.write(f"[{section}]\n\t{name}\n")
                        else:
                            git(destination, "config", "--local", key, value)
                        injected = True
                    return result

                with mock.patch.object(
                    named_lane_runtime,
                    "run_bounded_capture",
                    side_effect=inject_config,
                ):
                    with self.assertRaisesRegex(NamedLaneGuardError, expected):
                        materialize_worktree(
                            self.repo.resolve(),
                            destination,
                            base,
                            head,
                        )

                self.assertTrue(injected)
                self.assertFalse(destination.exists())
                self.assertFalse(marker.exists())
                self.assertFalse(any("checkout" in command for command in commands))

    def test_materializer_rejects_alternates_shallow_and_promisor_state(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        original_capture = named_lane_runtime.run_bounded_capture
        cases = (
            ("commondir", "commondir state"),
            ("alternates-empty", "alternates must be absent"),
            ("alternates-nonempty", "alternates must be absent"),
            ("http-alternates-empty", "HTTP alternates must be absent"),
            (
                "arbitrary-shallow",
                "materialized Git shallow repository state is not allowed",
            ),
            ("promisor", "promisor state"),
            ("promisor-mixed-case", "promisor state"),
            ("missing-object", "object inventory does not match"),
        )

        for label, expected in cases:
            with self.subTest(label=label):
                destination = self.root / f"unsafe-{label}-storage"
                injected = False

                def inject_storage(argv: object, **kwargs: object) -> object:
                    nonlocal injected
                    command = tuple(argv)
                    result = original_capture(command, **kwargs)
                    injection_point = (
                        "index-pack" in command
                        if label == "missing-object"
                        else "init" in command
                    )
                    if not injected and injection_point:
                        if label == "commondir":
                            (destination / ".git" / "commondir").write_text(
                                "../shared\n",
                                encoding="utf-8",
                            )
                        elif label.startswith("alternates-"):
                            info = destination / ".git" / "objects" / "info"
                            info.mkdir(exist_ok=True)
                            content = (
                                ""
                                if label == "alternates-empty"
                                else str(self.repo / ".git" / "objects") + "\n"
                            )
                            (info / "alternates").write_text(content, encoding="utf-8")
                        elif label == "http-alternates-empty":
                            info = destination / ".git" / "objects" / "info"
                            info.mkdir(exist_ok=True)
                            (info / "http-alternates").write_text(
                                "",
                                encoding="utf-8",
                            )
                        elif label == "arbitrary-shallow":
                            (destination / ".git" / "shallow").write_text(
                                head + "\n",
                                encoding="ascii",
                            )
                        elif label in {"promisor", "promisor-mixed-case"}:
                            pack = destination / ".git" / "objects" / "pack"
                            pack.mkdir(exist_ok=True)
                            suffix = (
                                "injected.promisor"
                                if label == "promisor"
                                else "injected.PrOmIsOr"
                            )
                            (pack / suffix).write_bytes(b"")
                        else:
                            for packed_object in (
                                destination / ".git" / "objects" / "pack"
                            ).iterdir():
                                packed_object.unlink()
                        injected = True
                    return result

                with mock.patch.object(
                    named_lane_runtime,
                    "run_bounded_capture",
                    side_effect=inject_storage,
                ):
                    with self.assertRaisesRegex(NamedLaneGuardError, expected):
                        materialize_worktree(
                            self.repo.resolve(),
                            destination,
                            base,
                            head,
                        )

                self.assertTrue(injected)
                self.assertFalse(destination.exists())

    def test_materializer_does_not_initialize_submodules(self) -> None:
        head = self.add_deinitialized_gitlink()
        base = git(self.repo, "rev-parse", "HEAD^")
        git(self.repo, "config", "submodule.recurse", "true")
        destination = self.root / "submodule-lane"

        result = materialize_worktree(
            self.repo.resolve(),
            destination,
            base,
            head,
        )

        self.assertEqual(result.head_sha, head)
        gitlink = destination / "vendor"
        if gitlink.exists():
            self.assertTrue(gitlink.is_dir())
            self.assertEqual(list(gitlink.iterdir()), [])
        self.assertEqual(validate_worktree(destination, base, head).head_sha, head)

    def test_materializer_reports_exact_retained_path_when_cleanup_fails(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        destination = self.root / "retained-lane"
        original_capture = named_lane_runtime.run_bounded_capture
        original_rmtree = named_lane_runtime.shutil.rmtree
        injected = False

        def inject_config(argv: object, **kwargs: object) -> object:
            nonlocal injected
            command = tuple(argv)
            result = original_capture(command, **kwargs)
            if not injected and "init" in command:
                git(destination, "config", "core.fsmonitor", "/usr/bin/false")
                injected = True
            return result

        def retain_destination(path: object, *args: object, **kwargs: object) -> None:
            if pathlib.Path(path) == destination:
                raise OSError("simulated cleanup failure")
            original_rmtree(path, *args, **kwargs)

        with (
            mock.patch.object(
                named_lane_runtime,
                "run_bounded_capture",
                side_effect=inject_config,
            ),
            mock.patch.object(
                named_lane_runtime.shutil,
                "rmtree",
                side_effect=retain_destination,
            ),
        ):
            with self.assertRaisesRegex(
                NamedLaneGuardError,
                f"retained materialized worktree: {re.escape(str(destination))}",
            ):
                materialize_worktree(
                    self.repo.resolve(),
                    destination,
                    base,
                    head,
                )

        self.assertTrue(injected)
        self.assertTrue(destination.exists())

    def test_materializer_cleanup_preserves_a_replaced_directory(self) -> None:
        target = self.root / "cleanup-target"
        target.mkdir(mode=0o700)
        expected_identity = named_lane_runtime._directory_identity(target.lstat())
        original = self.root / "original-cleanup-target"
        target.rename(original)
        target.mkdir(mode=0o700)

        retained = named_lane_runtime._cleanup_materializer_path(
            target,
            self.root,
            named_lane_runtime._directory_identity(self.root.lstat()),
            expected_identity,
        )

        self.assertEqual(retained, target)
        self.assertTrue(target.is_dir())
        self.assertTrue(original.is_dir())

    def test_materializer_cleanup_propagates_control_flow_base_exceptions(
        self,
    ) -> None:
        for control_flow in (
            KeyboardInterrupt(),
            SystemExit(7),
            ForwardedSignal(signal.SIGTERM),
        ):
            with self.subTest(control_flow=type(control_flow).__name__):
                target = self.root / f"cleanup-{type(control_flow).__name__}"
                target.mkdir(mode=0o700)
                expected_identity = named_lane_runtime._directory_identity(
                    target.lstat()
                )
                with mock.patch.object(
                    named_lane_runtime.shutil,
                    "rmtree",
                    side_effect=control_flow,
                ):
                    with self.assertRaises(type(control_flow)):
                        named_lane_runtime._cleanup_materializer_path(
                            target,
                            self.root,
                            named_lane_runtime._directory_identity(self.root.lstat()),
                            expected_identity,
                        )

    @retired_public_commands("materialize-worktree")
    def test_materializer_cli_structures_signal_during_python_cleanup_window(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        destination = self.root / "signal-cleanup-lane"
        interrupted = False

        def interrupt_storage(
            _git_directory: pathlib.Path,
            **_kwargs: object,
        ) -> None:
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                signal.raise_signal(signal.SIGINT)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                named_lane_runtime,
                "_validate_materialized_object_storage",
                side_effect=interrupt_storage,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                (
                    "materialize-worktree",
                    "--source",
                    str(self.repo.resolve()),
                    "--worktree",
                    str(destination),
                    "--base",
                    base,
                    "--head",
                    head,
                )
            )

        self.assertTrue(interrupted)
        self.assertEqual(returncode, 128 + signal.SIGINT)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {"status": "blocked-safety", "reason": "forwarded-signal"},
        )
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".named-lane-materializer-*")), [])

    @retired_public_commands("materialize-worktree")
    def test_materializer_cli_preserves_retained_control_path_at_terminal_restore(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        destination = self.root / "control-setup-failure-lane"
        original_mkdir = pathlib.Path.mkdir
        original_rmtree = named_lane_runtime.shutil.rmtree
        original_restore = named_lane_runtime.restore_signal_mask
        restore_calls = 0

        def fail_control_child(
            path: pathlib.Path,
            *args: object,
            **kwargs: object,
        ) -> None:
            if path.name == "xdg" and path.parent.name.startswith(
                ".named-lane-materializer-"
            ):
                raise OSError("simulated control setup failure")
            original_mkdir(path, *args, **kwargs)

        def retain_control(path: object, *args: object, **kwargs: object) -> None:
            if pathlib.Path(path).name.startswith(".named-lane-materializer-"):
                raise OSError("simulated control cleanup failure")
            original_rmtree(path, *args, **kwargs)

        def interrupt_terminal_restore(previous: object) -> None:
            nonlocal restore_calls
            restore_calls += 1
            if restore_calls == 2:
                signal.raise_signal(signal.SIGINT)
            original_restore(previous)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                pathlib.Path,
                "mkdir",
                autospec=True,
                side_effect=fail_control_child,
            ),
            mock.patch.object(
                named_lane_runtime.shutil,
                "rmtree",
                side_effect=retain_control,
            ),
            mock.patch.object(
                named_lane_runtime,
                "restore_signal_mask",
                side_effect=interrupt_terminal_restore,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                (
                    "materialize-worktree",
                    "--source",
                    str(self.repo.resolve()),
                    "--worktree",
                    str(destination),
                    "--base",
                    base,
                    "--head",
                    head,
                )
            )

        retained_controls = list(self.root.glob(".named-lane-materializer-*"))
        self.assertEqual(len(retained_controls), 1)
        self.assertGreaterEqual(restore_calls, 5)
        self.assertEqual(returncode, 2)
        self.assertEqual(stdout.getvalue(), "")
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["status"], "blocked-safety")
        self.assertIn(
            f"retained control path: {retained_controls[0]}",
            payload["reason"],
        )
        self.assertNotEqual(payload["reason"], "forwarded-signal")
        self.assertFalse(destination.exists())

    @retired_public_commands("materialize-worktree")
    def test_materializer_cli_defers_signal_during_control_cleanup(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        destination = self.root / "cleanup-signal-lane"
        original_rmtree = named_lane_runtime.shutil.rmtree
        interrupted = False

        def interrupt_control_cleanup(
            path: object,
            *args: object,
            **kwargs: object,
        ) -> None:
            nonlocal interrupted
            candidate = pathlib.Path(path)
            if not interrupted and candidate.name.startswith(
                ".named-lane-materializer-"
            ):
                interrupted = True
                signal.raise_signal(signal.SIGINT)
            original_rmtree(path, *args, **kwargs)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                named_lane_runtime.shutil,
                "rmtree",
                side_effect=interrupt_control_cleanup,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                (
                    "materialize-worktree",
                    "--source",
                    str(self.repo.resolve()),
                    "--worktree",
                    str(destination),
                    "--base",
                    base,
                    "--head",
                    head,
                )
            )

        self.assertTrue(interrupted)
        self.assertEqual(returncode, 128 + signal.SIGINT)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {"status": "blocked-safety", "reason": "forwarded-signal"},
        )
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".named-lane-materializer-*")), [])

    @retired_public_commands("materialize-worktree")
    def test_materializer_cli_retries_signal_block_before_cleanup(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        destination = self.root / "cleanup-block-signal-lane"
        original_block = named_lane_runtime.block_forwarded_signals
        block_calls = 0

        def interrupt_before_cleanup_block() -> object:
            nonlocal block_calls
            block_calls += 1
            if block_calls == 3:
                signal.raise_signal(signal.SIGINT)
            return original_block()

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                named_lane_runtime,
                "block_forwarded_signals",
                side_effect=interrupt_before_cleanup_block,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                (
                    "materialize-worktree",
                    "--source",
                    str(self.repo.resolve()),
                    "--worktree",
                    str(destination),
                    "--base",
                    base,
                    "--head",
                    head,
                )
            )

        self.assertGreaterEqual(block_calls, 4)
        self.assertEqual(returncode, 128 + signal.SIGINT)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {"status": "blocked-safety", "reason": "forwarded-signal"},
        )
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".named-lane-materializer-*")), [])

    @retired_public_commands("materialize-worktree")
    def test_materializer_cli_receipt_commits_a_signal_during_emit(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        destination = self.root / "receipt-signal-lane"
        original_emit = named_lane_runtime._emit
        interrupted = False

        def interrupt_receipt(
            payload: dict[str, object],
            *,
            stream: object | None = None,
        ) -> None:
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                signal.raise_signal(signal.SIGINT)
            original_emit(payload, stream=sys.stdout if stream is None else stream)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                named_lane_runtime,
                "_emit",
                side_effect=interrupt_receipt,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                (
                    "materialize-worktree",
                    "--source",
                    str(self.repo.resolve()),
                    "--worktree",
                    str(destination),
                    "--base",
                    base,
                    "--head",
                    head,
                )
            )

        self.assertTrue(interrupted)
        self.assertEqual(returncode, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {
                "status": "ok",
                "worktree": str(destination),
                "base": base,
                "head": head,
                "commit_count": 2,
                "parent_edge_count": 1,
                "parent_graph_sha256": mock.ANY,
                "local_config_sha256": mock.ANY,
            },
        )
        self.assertEqual(validate_worktree(destination, base, head).head_sha, head)

    @retired_public_commands("materialize-worktree")
    def test_materializer_cli_receipt_commits_signal_while_unblocking(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        destination = self.root / "receipt-unblock-signal-lane"
        original_restore = named_lane_runtime.restore_signal_mask
        original_emit = named_lane_runtime._emit
        receipt_published = False
        signal_injected = False

        def record_receipt(
            payload: dict[str, object],
            *,
            stream: object | None = None,
        ) -> None:
            nonlocal receipt_published
            original_emit(payload, stream=stream)
            if stream is None:
                receipt_published = True

        def interrupt_receipt_unblock(previous: object) -> None:
            nonlocal signal_injected
            if receipt_published and not signal_injected:
                signal_injected = True
                signal.raise_signal(signal.SIGINT)
            original_restore(previous)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                named_lane_runtime,
                "restore_signal_mask",
                side_effect=interrupt_receipt_unblock,
            ),
            mock.patch.object(
                named_lane_runtime,
                "_emit",
                side_effect=record_receipt,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                (
                    "materialize-worktree",
                    "--source",
                    str(self.repo.resolve()),
                    "--worktree",
                    str(destination),
                    "--base",
                    base,
                    "--head",
                    head,
                )
            )

        self.assertTrue(signal_injected)
        self.assertEqual(returncode, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(json.loads(stdout.getvalue())["status"], "ok")
        self.assertEqual(validate_worktree(destination, base, head).head_sha, head)

    @retired_public_commands("materialize-worktree")
    def test_materializer_cli_receipt_commits_signal_during_outer_teardown(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        destination = self.root / "receipt-teardown-signal-lane"
        original_block = named_lane_runtime.block_forwarded_signals
        original_emit = named_lane_runtime._emit
        receipt_published = False
        signal_injected = False

        def record_receipt(
            payload: dict[str, object],
            *,
            stream: object | None = None,
        ) -> None:
            nonlocal receipt_published
            original_emit(payload, stream=stream)
            if stream is None:
                receipt_published = True

        def interrupt_outer_teardown() -> object:
            nonlocal signal_injected
            mask = original_block()
            if receipt_published and not signal_injected:
                signal_injected = True
                signal.raise_signal(signal.SIGINT)
            return mask

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                named_lane_runtime,
                "block_forwarded_signals",
                side_effect=interrupt_outer_teardown,
            ),
            mock.patch.object(
                named_lane_runtime,
                "_emit",
                side_effect=record_receipt,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                (
                    "materialize-worktree",
                    "--source",
                    str(self.repo.resolve()),
                    "--worktree",
                    str(destination),
                    "--base",
                    base,
                    "--head",
                    head,
                )
            )

        self.assertTrue(signal_injected)
        self.assertEqual(returncode, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(json.loads(stdout.getvalue())["status"], "ok")
        self.assertEqual(validate_worktree(destination, base, head).head_sha, head)

    @retired_public_commands("materialize-worktree")
    def test_materializer_cli_retains_terminal_failure_when_signal_arrives_during_receipt_rollback(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        destination = self.root / "receipt-rollback-retained-lane"
        original_emit = named_lane_runtime._emit
        original_rmtree = named_lane_runtime.shutil.rmtree
        original_restore = named_lane_runtime.restore_signal_mask
        receipt_failed = False
        cleanup_failed = False
        restore_calls = 0

        def fail_receipt(
            payload: dict[str, object],
            *,
            stream: object | None = None,
        ) -> None:
            nonlocal receipt_failed
            if stream is None and not receipt_failed:
                receipt_failed = True
                raise BrokenPipeError("simulated receipt failure")
            original_emit(payload, stream=stream)

        def retain_destination(path: object, *args: object, **kwargs: object) -> None:
            nonlocal cleanup_failed
            if pathlib.Path(path) == destination:
                cleanup_failed = True
                signal.raise_signal(signal.SIGINT)
                raise RecursionError("simulated deep-tree rollback failure")
            original_rmtree(path, *args, **kwargs)

        def interrupt_outer_terminal_teardown(previous: object) -> None:
            nonlocal restore_calls
            restore_calls += 1
            if restore_calls == 5:
                signal.raise_signal(signal.SIGINT)
            original_restore(previous)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                named_lane_runtime,
                "_emit",
                side_effect=fail_receipt,
            ),
            mock.patch.object(
                named_lane_runtime.shutil,
                "rmtree",
                side_effect=retain_destination,
            ),
            mock.patch.object(
                named_lane_runtime,
                "restore_signal_mask",
                side_effect=interrupt_outer_terminal_teardown,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                (
                    "materialize-worktree",
                    "--source",
                    str(self.repo.resolve()),
                    "--worktree",
                    str(destination),
                    "--base",
                    base,
                    "--head",
                    head,
                )
            )

        self.assertTrue(receipt_failed)
        self.assertTrue(cleanup_failed)
        self.assertGreaterEqual(restore_calls, 5)
        self.assertEqual(returncode, 2)
        self.assertEqual(stdout.getvalue(), "")
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["status"], "blocked-safety")
        self.assertIn("simulated receipt failure", payload["reason"])
        self.assertIn(
            f"retained materialized worktree: {destination}",
            payload["reason"],
        )
        self.assertNotEqual(payload["reason"], "forwarded-signal")
        self.assertTrue(destination.exists())

    def test_safe_internal_source_symlink_is_allowed(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        (self.repo / "target.txt").write_text("tracked\n", encoding="utf-8")
        (self.repo / "source-link").symlink_to("target.txt")
        head = self.commit()

        result = self.validate_repo(head)

        self.assertEqual(result.symlink_count, 1)
        self.assertEqual(result.guidance_count, 1)

    def test_symlink_targets_use_one_binary_safe_bounded_batch(self) -> None:
        first_object = "1" * 40
        second_object = "2" * 40
        first_target = b"nested/target\nwith-newline"
        second_target = b"other-target"
        payload = (
            f"{first_object} blob {len(first_target)}\n".encode("ascii")
            + first_target
            + b"\n"
            + f"{second_object} blob {len(second_target)}\n".encode("ascii")
            + second_target
            + b"\n"
        )

        with mock.patch(
            "review_runtime.named_lane._git_capture", return_value=payload
        ) as capture:
            targets = _read_symlink_blobs(
                self.repo.resolve(),
                (first_object, first_object, second_object),
            )

        self.assertEqual(targets[first_object], os.fsdecode(first_target))
        self.assertEqual(targets[second_object], os.fsdecode(second_target))
        capture.assert_called_once()
        arguments, keywords = capture.call_args
        self.assertEqual(arguments[1], ("cat-file", "--batch"))
        self.assertEqual(
            keywords["stdin"],
            bytearray(f"{first_object}\n{second_object}\n".encode("ascii")),
        )

    def test_symlink_batch_has_an_explicit_aggregate_count_limit(self) -> None:
        object_ids = tuple(f"{value:040x}" for value in range(SYMLINK_COUNT_LIMIT + 1))

        with mock.patch("review_runtime.named_lane._git_capture") as capture:
            with self.assertRaisesRegex(NamedLaneGuardError, "too many symlinks"):
                _read_symlink_blobs(self.repo.resolve(), object_ids)

        capture.assert_not_called()

    def test_worktree_path_through_symlink_ancestor_is_allowed(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        ancestor = self.root / "ancestor"
        ancestor.symlink_to(self.root, target_is_directory=True)

        self.bind_formal_validator_range(head, head)
        result = validate_worktree((ancestor / self.repo.name).absolute(), head, head)

        self.assertEqual(result.root, self.repo.resolve())

    def test_worktree_path_with_symlink_leaf_is_rejected(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        worktree_link = self.root / "worktree-link"
        worktree_link.symlink_to(self.repo, target_is_directory=True)

        with self.assertRaisesRegex(NamedLaneGuardError, "real directory"):
            validate_worktree(worktree_link.absolute(), head, head)

    def test_absolute_and_relative_escaping_symlinks_are_rejected(self) -> None:
        for target in (str(self.root / "outside"), "../outside"):
            with self.subTest(target=target):
                link = self.repo / "escape"
                link.unlink(missing_ok=True)
                link.symlink_to(target)
                head = self.commit(f"escape {target}")
                with self.assertRaisesRegex(NamedLaneGuardError, "escapes"):
                    self.validate_repo(head)

    def test_ignored_transitive_link_is_rejected_at_pristine_gate(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        (self.repo / ".gitignore").write_text("bridge\n", encoding="utf-8")
        (self.repo / "review-link").symlink_to("bridge")
        head = self.commit()
        (self.repo / "bridge").symlink_to(self.root / "outside")
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

        with self.assertRaisesRegex(NamedLaneGuardError, "must be clean"):
            self.validate_repo(head)

    def test_guidance_symlink_is_rejected_even_when_it_stays_inside(self) -> None:
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "rules.md").write_text("rules\n", encoding="utf-8")
        (self.repo / "AGENTS.md").symlink_to("docs/rules.md")
        head = self.commit()

        with self.assertRaisesRegex(NamedLaneGuardError, "guidance must"):
            self.validate_repo(head)

    def test_materialized_symlink_mismatch_is_rejected(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        (self.repo / "target.txt").write_text("target\n", encoding="utf-8")
        link = self.repo / "source-link"
        link.symlink_to("target.txt")
        head = self.commit()
        git(self.repo, "update-index", "--assume-unchanged", "source-link")
        link.unlink()
        link.symlink_to("AGENTS.md")
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

        with self.assertRaisesRegex(
            NamedLaneGuardError, "differs from the frozen tree"
        ):
            _validate_materialized_symlink(
                self.repo.resolve(),
                pathlib.PurePosixPath("source-link"),
                "target.txt",
            )
        with self.assertRaisesRegex(NamedLaneGuardError, "assume-unchanged"):
            self.validate_repo(head)

    def test_skip_worktree_index_bit_is_rejected(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        git(self.repo, "update-index", "--skip-worktree", "AGENTS.md")

        with self.assertRaisesRegex(NamedLaneGuardError, "skip-worktree"):
            self.validate_repo(head)

    def test_ignored_artifact_is_rejected_even_when_default_status_is_clean(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        (self.repo / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
        head = self.commit()
        (self.repo / "ignored.txt").write_text("artifact\n", encoding="utf-8")
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

        with self.assertRaisesRegex(NamedLaneGuardError, "must be clean"):
            self.validate_repo(head)

    def test_gitlink_may_be_absent_or_an_empty_real_directory(self) -> None:
        head = self.add_deinitialized_gitlink()
        self.assertEqual(list((self.repo / "vendor").iterdir()), [])
        (self.repo / "vendor").chmod(0o700)
        os.utime(self.repo / "vendor", None)
        empty = self.validate_repo(head)
        self.assertEqual(empty.head_sha, head)

        (self.repo / "vendor").rmdir()
        missing = self.validate_repo(head)
        self.assertEqual(missing.head_sha, head)

    def test_gitlink_rejects_materialized_content_symlink_and_regular_file(
        self,
    ) -> None:
        self.add_gitlink()
        gitlink = self.repo / "vendor"
        gitlink.mkdir()
        (gitlink / ".git").write_text("gitdir: elsewhere\n", encoding="utf-8")
        with self.assertRaisesRegex(NamedLaneGuardError, "uninitialized"):
            _validate_materialized_gitlink(
                self.repo.resolve(), pathlib.PurePosixPath("vendor")
            )

        (gitlink / ".git").unlink()
        gitlink.rmdir()
        gitlink.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(NamedLaneGuardError, "empty real directory"):
            _validate_materialized_gitlink(
                self.repo.resolve(), pathlib.PurePosixPath("vendor")
            )

        gitlink.unlink()
        ancestor = self.repo / "nested"
        ancestor.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(NamedLaneGuardError, "empty real directory"):
            _validate_materialized_gitlink(
                self.repo.resolve(), pathlib.PurePosixPath("nested/vendor")
            )

        gitlink.write_text("not a submodule\n", encoding="utf-8")
        with self.assertRaisesRegex(NamedLaneGuardError, "empty real directory"):
            _validate_materialized_gitlink(
                self.repo.resolve(), pathlib.PurePosixPath("vendor")
            )

    def test_initialized_clean_submodule_is_rejected_end_to_end(self) -> None:
        head = self.add_deinitialized_gitlink()
        git(
            self.repo,
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "update",
            "--init",
            "--",
            "vendor",
        )
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            self.validate_repo(head)

    def test_materialized_gitlink_is_rejected_before_external_gitdir_access(
        self,
    ) -> None:
        head = self.add_gitlink()
        gitlink = self.repo / "vendor"
        gitlink.mkdir()
        external_gitdir = self.root / "external.git"
        external_gitdir.mkdir()
        git(external_gitdir, "init", "--bare")
        (gitlink / ".git").write_text(
            f"gitdir: {external_gitdir}\n",
            encoding="utf-8",
        )

        external_gitdir.chmod(0)
        try:
            with self.assertRaisesRegex(NamedLaneGuardError, "uninitialized"):
                self.validate_repo(head)
        finally:
            external_gitdir.chmod(0o700)

    def test_initialized_unpopulated_submodule_is_rejected_end_to_end(self) -> None:
        head = self.add_deinitialized_gitlink()
        git(
            self.repo,
            "config",
            "submodule.unrelated.url",
            str(self.root / "unrelated"),
        )
        clean = self.validate_repo(head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "submodule", "init", "--", "vendor")
        self.assertEqual(list((self.repo / "vendor").iterdir()), [])
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            self.validate_repo(head)

    def test_per_worktree_initialized_submodule_config_is_rejected(self) -> None:
        head = self.add_deinitialized_gitlink()
        git(self.repo, "config", "extensions.worktreeConfig", "true")
        git(
            self.repo,
            "config",
            "--worktree",
            "submodule.unrelated.url",
            str(self.root / "unrelated"),
        )
        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "per-worktree Git config is not allowed",
        ):
            self.validate_repo(head)

    def test_global_submodule_active_uses_git_pathspec_precedence(self) -> None:
        head = self.add_deinitialized_gitlink()

        git(self.repo, "config", "submodule.unrelated.active", "not-a-boolean")
        git(self.repo, "config", "submodule.active", "unrelated")
        clean = self.validate_repo(head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "config", "--replace-all", "submodule.active", "true")
        clean = self.validate_repo(head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "config", "--replace-all", "submodule.active", "vendor")
        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            self.validate_repo(head)

        git(self.repo, "config", "--replace-all", "submodule.active", "*")
        git(self.repo, "config", "--add", "submodule.active", ":(exclude)vendor")
        clean = self.validate_repo(head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "config", "--replace-all", "submodule.active", "vendor")
        git(self.repo, "config", "submodule.vendor.active", "false")
        clean = self.validate_repo(head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "config", "submodule.vendor.active", "true")
        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            self.validate_repo(head)

    def test_global_submodule_active_reads_worktree_and_blocks_included_config(
        self,
    ) -> None:
        head = self.add_deinitialized_gitlink()
        git(self.repo, "config", "extensions.worktreeConfig", "true")
        git(self.repo, "config", "--worktree", "submodule.active", "vendor")
        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "per-worktree Git config is not allowed",
        ):
            self.validate_repo(head)
        git(
            self.repo,
            "config",
            "--worktree",
            "--unset-all",
            "submodule.active",
        )
        (self.repo / ".git" / "config.worktree").unlink()
        git(self.repo, "config", "--unset-all", "extensions.worktreeConfig")

        included = self.root / "included-submodule-active.config"
        included.write_text("[submodule]\n\tactive = vendor\n", encoding="utf-8")
        git(self.repo, "config", "include.path", str(included))
        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "Git config include directives are not allowed",
        ):
            self.validate_repo(head)

    def test_raw_gitlink_effective_path_uses_registration_and_activation(
        self,
    ) -> None:
        head = self.add_gitlink()
        self.assertFalse((self.repo / ".gitmodules").exists())
        git(self.repo, "config", "submodule.unrelated.path", "elsewhere")
        git(
            self.repo,
            "config",
            "submodule.unrelated.url",
            str(self.root / "unrelated"),
        )
        clean = self.validate_repo(head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "config", "submodule.named.path", "vendor")
        clean = self.validate_repo(head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "config", "submodule.active", "vendor")
        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            self.validate_repo(head)

        git(self.repo, "config", "submodule.named.active", "false")
        clean = self.validate_repo(head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "config", "submodule.named.active", "true")
        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            self.validate_repo(head)

        git(self.repo, "config", "--unset-all", "submodule.active")
        git(self.repo, "config", "--unset-all", "submodule.named.active")
        git(
            self.repo,
            "config",
            "submodule.named.url",
            str(self.root / "submodule-source"),
        )
        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            self.validate_repo(head)

        git(self.repo, "config", "--unset-all", "submodule.named.path")
        git(self.repo, "config", "--unset-all", "submodule.named.url")
        git(self.repo, "config", "submodule.vendor.active", "true")
        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            self.validate_repo(head)

    def test_raw_gitlink_reads_worktree_submodule_path_config(self) -> None:
        head = self.add_gitlink()
        git(self.repo, "config", "extensions.worktreeConfig", "true")
        git(self.repo, "config", "--worktree", "submodule.named.path", "vendor")
        git(self.repo, "config", "--worktree", "submodule.named.active", "true")

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "per-worktree Git config is not allowed",
        ):
            self.validate_repo(head)

    def test_raw_gitlink_without_mapping_honors_global_submodule_active(
        self,
    ) -> None:
        head = self.add_gitlink()

        git(self.repo, "config", "submodule.active", "vendor")
        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            self.validate_repo(head)

        git(self.repo, "config", "--replace-all", "submodule.active", "unrelated")
        clean = self.validate_repo(head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "config", "--replace-all", "submodule.active", "*")
        git(self.repo, "config", "--add", "submodule.active", ":(exclude)vendor")
        clean = self.validate_repo(head)
        self.assertEqual(clean.head_sha, head)

    def test_raw_gitlink_blocks_included_submodule_path_config(self) -> None:
        head = self.add_gitlink()
        included = self.root / "included-raw-submodule.config"
        included.write_text(
            '[submodule "named"]\n'
            "\tpath = vendor\n"
            f"\turl = {self.root / 'submodule-source'}\n",
            encoding="utf-8",
        )
        git(self.repo, "config", "include.path", str(included))

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "Git config include directives are not allowed",
        ):
            self.validate_repo(head)

    def test_empty_gitmodules_without_definitions_allows_absent_gitlink(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        (self.repo / ".gitmodules").write_text("", encoding="utf-8")
        target = self.commit("gitlink target")
        git(
            self.repo,
            "update-index",
            "--add",
            "--cacheinfo",
            "160000",
            target,
            "vendor",
        )
        git(self.repo, "commit", "-m", "add raw gitlink")
        head = git(self.repo, "rev-parse", "HEAD")

        result = self.validate_repo(head)

        self.assertEqual(result.head_sha, head)

    def test_malformed_gitmodules_is_not_treated_as_no_definitions(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        (self.repo / ".gitmodules").write_text(
            '[submodule "broken"\n', encoding="utf-8"
        )
        target = self.commit("gitlink target")
        git(
            self.repo,
            "update-index",
            "--add",
            "--cacheinfo",
            "160000",
            target,
            "vendor",
        )
        tree = git(self.repo, "write-tree")
        head = git(
            self.repo,
            "commit-tree",
            tree,
            "-p",
            target,
            "-m",
            "add raw gitlink",
        )
        git(self.repo, "update-ref", "refs/heads/master", head, target)
        self.bind_formal_validator_range(head, head)

        with self.assertRaisesRegex(
            NamedLaneGuardError, "bounded local Git preflight failed"
        ):
            self.validate_repo(head)

    @retired_public_commands("validate-worktree")
    def test_valueless_frozen_submodule_path_is_structured_blocked_safety(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        target = self.commit("gitlink target")
        (self.repo / ".gitmodules").write_text(
            '[submodule "vendor"]\n\tpath\n',
            encoding="utf-8",
        )
        git(
            self.repo,
            "update-index",
            "--add",
            "--cacheinfo",
            "160000",
            target,
            "vendor",
        )
        git(self.repo, "add", ".gitmodules")
        tree = git(self.repo, "write-tree")
        head = git(
            self.repo,
            "commit-tree",
            tree,
            "-p",
            target,
            "-m",
            "add valueless submodule path",
        )
        git(self.repo, "update-ref", "refs/heads/master", head, target)
        self.bind_formal_validator_range(head, head)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                (
                    "validate-worktree",
                    "--worktree",
                    str(self.repo.resolve()),
                    "--base",
                    head,
                    "--head",
                    head,
                )
            )

        self.assertEqual(returncode, 2)
        self.assertEqual(stdout.getvalue(), "")
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["status"], "blocked-safety")
        self.assertIn("malformed frozen submodule path record", payload["reason"])

    def test_valueless_effective_submodule_path_is_rejected(self) -> None:
        head = self.add_gitlink()
        with (self.repo / ".git" / "config").open(
            "a",
            encoding="utf-8",
        ) as handle:
            handle.write('[submodule "vendor"]\n\tpath\n')

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "malformed effective submodule path record",
        ):
            self.validate_repo(head)

    def test_guard_does_not_scan_ordinary_file_contents(self) -> None:
        (self.repo / "AGENTS.md").write_text(
            "synthetic-looking text sk-" + "A" * 48 + "\n",
            encoding="utf-8",
        )
        head = self.commit()

        result = self.validate_repo(head)

        self.assertEqual(result.symlink_count, 0)

    def test_exact_head_and_clean_status_are_required(self) -> None:
        tracked = self.repo / "AGENTS.md"
        tracked.write_text("one\n", encoding="utf-8")
        first = self.commit("first")
        tracked.write_text("two\n", encoding="utf-8")
        second = self.commit("second")

        self.bind_formal_validator_range(first, first)
        with self.assertRaisesRegex(NamedLaneGuardError, "does not match"):
            validate_worktree(self.repo.resolve(), first, first)

        tracked.write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(NamedLaneGuardError, "must be clean"):
            self.validate_repo(second)

        tracked.write_text("two\n", encoding="utf-8")
        untracked = self.repo / "untracked.txt"
        untracked.write_text("artifact\n", encoding="utf-8")
        with self.assertRaisesRegex(NamedLaneGuardError, "must be clean"):
            self.validate_repo(second)

        with self.assertRaisesRegex(NamedLaneGuardError, "full Git object ID"):
            validate_worktree(self.repo.resolve(), second, "--not-a-revision")

    @unittest.skipUnless(os.name == "posix", "file mode validation requires POSIX")
    def test_status_forces_filemode_checks_over_repository_config(self) -> None:
        tracked = self.repo / "review.sh"
        tracked.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        tracked.chmod(0o755)
        head = self.commit()
        git(self.repo, "config", "core.fileMode", "false")
        tracked.chmod(0o644)
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

        with self.assertRaisesRegex(NamedLaneGuardError, "must be clean"):
            self.validate_repo(head)

    def test_status_filter_commands_are_rejected_before_execution(self) -> None:
        tracked = self.repo / "AGENTS.md"
        tracked.write_text("clean\n", encoding="utf-8")
        (self.repo / ".gitattributes").write_text(
            "AGENTS.md filter=unsafe\n",
            encoding="utf-8",
        )
        head = self.commit()
        marker = self.root / "filter-command.marker"

        smudge = self.make_executable(
            f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
        )
        git(self.repo, "config", "filter.unsafe.smudge", str(smudge))
        clean = self.validate_repo(head)
        self.assertEqual(clean.head_sha, head)
        self.assertFalse(marker.exists())
        git(self.repo, "config", "--unset-all", "filter.unsafe.smudge")

        tracked.write_text("dirty\n", encoding="utf-8")
        for suffix in ("clean", "process"):
            with self.subTest(suffix=suffix):
                marker.unlink(missing_ok=True)
                source = (
                    f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
                )
                if suffix == "clean":
                    source += (
                        "import sys\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n"
                    )
                probe = self.make_executable(source)
                key = f"filter.unsafe.{suffix}"
                git(self.repo, "config", key, str(probe))
                with self.assertRaisesRegex(
                    NamedLaneGuardError,
                    "executable Git filter or diff commands",
                ):
                    self.validate_repo(head)
                self.assertFalse(marker.exists())
                git(self.repo, "config", "--unset-all", key)

    def test_included_filter_command_is_blocked_before_execution(self) -> None:
        tracked = self.repo / "AGENTS.md"
        tracked.write_text("clean\n", encoding="utf-8")
        (self.repo / ".gitattributes").write_text(
            "AGENTS.md filter=included\n",
            encoding="utf-8",
        )
        head = self.commit()
        tracked.write_text("dirty\n", encoding="utf-8")
        marker = self.root / "included-filter.marker"
        probe = self.make_executable(
            f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
        )
        included = self.root / "included-filter.config"
        included.write_text(
            f'[filter "included"]\n\tprocess = {probe}\n',
            encoding="utf-8",
        )
        git(self.repo, "config", "include.path", str(included))

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "Git config include directives are not allowed",
        ):
            self.validate_repo(head)
        self.assertFalse(marker.exists())

    def test_reviewer_executable_diff_config_is_rejected(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        marker = self.root / "diff-command.marker"
        probe = self.make_executable(
            f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
        )

        harmless = (
            ("diff.command", str(probe)),
            ("diff.textconv", str(probe)),
            ("diff.unsafe.binary", "true"),
            ("diff.unsafe.cachetextconv", "true"),
        )
        for key, value in harmless:
            git(self.repo, "config", key, value)
        clean = self.validate_repo(head)
        self.assertEqual(clean.head_sha, head)

        for key in (
            "diff.external",
            "diff.unsafe.command",
            "diff.unsafe.textconv",
        ):
            with self.subTest(key=key):
                git(self.repo, "config", key, str(probe))
                with self.assertRaisesRegex(
                    NamedLaneGuardError,
                    "executable Git filter or diff commands",
                ):
                    self.validate_repo(head)
                self.assertFalse(marker.exists())
                git(self.repo, "config", "--unset-all", key)

    @retired_public_commands("validate-worktree")
    def test_git_alias_is_blocked_before_reviewer_launch(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        self.bind_formal_validator_range(head, head)
        marker = self.root / "alias-reviewer-started.marker"
        probe = self.make_executable(
            f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
        )
        git(self.repo, "config", "extensions.worktreeConfig", "true")

        cases = (
            ((), "Git config aliases are not allowed before reviewer launch"),
            (
                ("--worktree",),
                "materialized per-worktree Git config is not allowed",
            ),
        )
        for scope, expected_reason in cases:
            with self.subTest(scope=scope or ("--local",)):
                git(self.repo, "config", *scope, "alias.foo", f"!{probe}")
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    returncode = self.named_lane_main(
                        (
                            "validate-worktree",
                            "--worktree",
                            str(self.repo.resolve()),
                            "--base",
                            head,
                            "--head",
                            head,
                        )
                    )

                self.assertEqual(returncode, 2)
                self.assertEqual(
                    json.loads(stderr.getvalue()),
                    {
                        "status": "blocked-safety",
                        "reason": expected_reason,
                    },
                )
                self.assertFalse(marker.exists())
                git(self.repo, "config", *scope, "--unset-all", "alias.foo")

    def test_included_config_is_blocked_and_worktree_diff_command_is_rejected(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        probe = self.make_executable("pass\n")
        included = self.root / "included-diff.config"
        included.write_text(
            f"[diff]\n\texternal = {probe}\n",
            encoding="utf-8",
        )
        git(self.repo, "config", "include.path", str(included))
        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "Git config include directives are not allowed",
        ):
            self.validate_repo(head)

        git(self.repo, "config", "--unset-all", "include.path")
        git(self.repo, "config", "extensions.worktreeConfig", "true")
        git(
            self.repo,
            "config",
            "--worktree",
            "diff.unsafe.textconv",
            str(probe),
        )
        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "per-worktree Git config is not allowed",
        ):
            self.validate_repo(head)

    def test_active_core_fsmonitor_config_is_rejected(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        marker = self.root / "fsmonitor.marker"
        probe = self.make_executable(
            f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
        )

        for disabled in ("", "false", "no", "off", "0"):
            with self.subTest(disabled=disabled):
                git(self.repo, "config", "core.fsmonitor", disabled)
                clean = self.validate_repo(head)
                self.assertEqual(clean.head_sha, head)

        for active in ("true", str(probe)):
            with self.subTest(active=active):
                git(self.repo, "config", "core.fsmonitor", active)
                with self.assertRaisesRegex(
                    NamedLaneGuardError,
                    "core.fsmonitor|bounded local Git preflight failed",
                ):
                    self.validate_repo(head)
                self.assertFalse(marker.exists())

        git(self.repo, "config", "--unset-all", "core.fsmonitor")
        config_path = self.repo / ".git" / "config"
        with config_path.open("a", encoding="utf-8") as config:
            config.write("\n[core]\n\tfsmonitor\n")
        with self.assertRaisesRegex(NamedLaneGuardError, "core.fsmonitor"):
            self.validate_repo(head)

    def test_core_fsmonitor_cannot_use_worktree_precedence(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        marker = self.root / "included-fsmonitor.marker"
        probe = self.make_executable(
            f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
        )
        git(self.repo, "config", "core.fsmonitor", str(probe))
        with self.assertRaisesRegex(NamedLaneGuardError, "core.fsmonitor"):
            self.validate_repo(head)
        self.assertFalse(marker.exists())

        git(self.repo, "config", "extensions.worktreeConfig", "true")
        git(self.repo, "config", "--worktree", "core.fsmonitor", "false")
        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "per-worktree Git config is not allowed",
        ):
            self.validate_repo(head)
        self.assertFalse(marker.exists())

    def test_external_include_is_blocked_without_using_external_config(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        marker = self.root / "external-include.marker"
        probe = self.make_executable(
            f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
        )
        included = self.root / "external.config"
        included.write_text(
            f"[core]\n\tfsmonitor = {probe}\n"
            '[credential "https://example.invalid"]\n'
            "\thelper = !external-secret-like-helper\n",
            encoding="utf-8",
        )
        git(self.repo, "config", "include.path", str(included))

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "Git config include directives are not allowed",
        ):
            self.validate_repo(head)
        self.assertFalse(marker.exists())

    def test_malformed_external_include_is_rejected_without_reading_it(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        included = self.root / "malformed-external.config"
        included.write_text("[broken\n", encoding="utf-8")
        git(self.repo, "config", "include.path", str(included))

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "Git config include directives are not allowed",
        ):
            self.validate_repo(head)

    def test_inactive_include_if_is_still_blocked(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        included = self.root / "inactive-include.config"
        included.write_text("[core]\n\tfsmonitor = false\n", encoding="utf-8")
        git(
            self.repo,
            "config",
            "includeIf.gitdir:/definitely/not/this/repository/.path",
            str(included),
        )

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "Git config include directives are not allowed",
        ):
            self.validate_repo(head)

    def test_per_worktree_include_is_blocked(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        included = self.root / "worktree-include.config"
        included.write_text("[core]\n\tfsmonitor = false\n", encoding="utf-8")
        git(self.repo, "config", "extensions.worktreeConfig", "true")
        git(self.repo, "config", "--worktree", "include.path", str(included))

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "per-worktree Git config is not allowed",
        ):
            self.validate_repo(head)

    def test_validate_worktree_uses_the_materializer_path_output_envelope(
        self,
    ) -> None:
        head = self.add_deinitialized_gitlink()
        git(self.repo, "config", "submodule.active", "unrelated")
        calls: list[tuple[tuple[str, ...], dict[str, object]]] = []
        original_capture = named_lane_runtime._git_capture

        def capture_call(
            root: pathlib.Path,
            arguments: object,
            **kwargs: object,
        ) -> bytes:
            calls.append((tuple(str(item) for item in arguments), dict(kwargs)))
            return original_capture(root, arguments, **kwargs)

        with mock.patch.object(
            named_lane_runtime,
            "_git_capture",
            side_effect=capture_call,
        ):
            result = self.validate_repo(head)

        self.assertEqual(result.head_sha, head)
        expected = named_lane_runtime._checkout_tree_output_limit(len(head))
        self.assertEqual(expected, 72_708_864)
        self.assertEqual(named_lane_runtime._checkout_tree_output_limit(64), 75_108_864)
        for subcommand in ("ls-tree", "ls-files", "status"):
            matching = [
                kwargs
                for command, kwargs in calls
                if subcommand in command
                and (subcommand != "ls-files" or "-v" in command)
            ]
            self.assertEqual(len(matching), 1)
            self.assertEqual(matching[0].get("output_limit_bytes"), expected)
        pathspec_calls = [
            kwargs
            for command, kwargs in calls
            if "ls-files" in command
            and any(item.startswith("--with-tree=") for item in command)
        ]
        self.assertEqual(len(pathspec_calls), 1)
        self.assertEqual(pathspec_calls[0].get("output_limit_bytes"), expected)

    def test_successful_process_writes_private_bounded_outputs(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable(
            "import sys\n"
            "payload = sys.stdin.buffer.read()\n"
            "sys.stdout.buffer.write(payload)\n"
            "sys.stderr.buffer.write(b'err')\n"
        )
        stdout = self.root / "stdout.bin"
        stderr = self.root / "stderr.bin"

        result = self.run_claude(
            worktree=self.repo.resolve(),
            stdout_path=stdout,
            stderr_path=stderr,
            command=(str(executable),),
            prompt=b"review",
            timeout_seconds=2.0,
            stream_limit_bytes=64,
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(stdout.read_bytes(), b"review")
        self.assertEqual(stderr.read_bytes(), b"err")
        self.assertEqual(stat.S_IMODE(stdout.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(stderr.stat().st_mode), 0o600)
        self.assertEqual(result["launch_binding"]["mode"], "verified-snapshot")
        self.assertEqual(tuple(self.root.glob(".named-lane-*")), ())

    def test_cli_run_claude_uses_the_preflight_bound_snapshot(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable(
            "import sys\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n"
        )
        stdout_path = self.root / "cli-bound.stdout"
        stderr_path = self.root / "cli-bound.stderr"

        completed = subprocess.run(
            self.isolated_guard_command(
                SCRIPTS / "named_lane_guard",
                "run-claude",
                "--worktree",
                str(self.repo.resolve()),
                "--source-worktree",
                str(self.source_control),
                "--preflight-result",
                str(self.preflight_result_path(executable)),
                "--stdout-path",
                str(stdout_path),
                "--stderr-path",
                str(stderr_path),
                "--timeout-seconds",
                "5",
                "--",
                str(executable),
            ),
            check=True,
            input=b"review",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )

        receipt = json.loads(completed.stdout)
        self.assertEqual(receipt["status"], "complete")
        self.assertEqual(receipt["launch_binding"]["mode"], "verified-snapshot")
        self.assertEqual(stdout_path.read_bytes(), b"review")
        self.assertEqual(stderr_path.read_bytes(), b"")
        self.assertEqual(tuple(self.root.glob(".named-lane-*")), ())

    def test_cli_run_claude_rejects_caller_owned_arguments(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        marker = self.root / "caller-argv-cli.marker"
        executable = self.make_executable(
            f"import pathlib\npathlib.Path({str(marker)!r}).touch()\n"
        )
        stdout_path = self.root / "caller-argv-cli.stdout"
        stderr_path = self.root / "caller-argv-cli.stderr"

        completed = subprocess.run(
            self.isolated_guard_command(
                SCRIPTS / "named_lane_guard",
                "run-claude",
                "--worktree",
                str(self.repo.resolve()),
                "--source-worktree",
                str(self.source_control),
                "--preflight-result",
                str(self.preflight_result_path(executable)),
                "--stdout-path",
                str(stdout_path),
                "--stderr-path",
                str(stderr_path),
                "--timeout-seconds",
                "5",
                "--",
                str(executable),
                "--safe-mode",
            ),
            check=False,
            input=b"review",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, b"")
        self.assertIn(
            "arguments are owned by the named-lane guard",
            json.loads(completed.stderr)["reason"],
        )
        self.assertFalse(marker.exists())
        self.assertFalse(stdout_path.exists())
        self.assertFalse(stderr_path.exists())

    def test_process_rejects_a_command_that_differs_from_preflight(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        accepted = self.make_executable("pass\n")
        different = self.make_executable("raise SystemExit(97)\n")
        stdout = self.root / "different-command.out"
        stderr = self.root / "different-command.err"

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "does not match the accepted preflight executable",
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=stdout,
                stderr_path=stderr,
                command=(str(different),),
                preflight_result=self.preflight_result_path(accepted),
                prompt=b"",
                timeout_seconds=5.0,
                stream_limit_bytes=64,
            )

        self.assertFalse(stdout.exists())
        self.assertFalse(stderr.exists())

    def test_process_rejects_executable_replacement_before_binding(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        accepted = self.make_executable("pass\n")
        malicious_marker = self.root / "replacement-before.marker"
        replacement = self.make_executable(
            "import pathlib\n"
            f"pathlib.Path({str(malicious_marker)!r}).write_text('ran')\n"
        )
        os.replace(replacement, accepted)

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "changed after accepted preflight",
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "replacement-before.out",
                stderr_path=self.root / "replacement-before.err",
                command=(str(accepted),),
                preflight_result=self.preflight_result_path(accepted),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=64,
            )

        self.assertFalse(malicious_marker.exists())

    def test_process_executes_bound_snapshot_when_source_is_replaced_and_restored(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        accepted = self.make_executable(
            "import sys\nsys.stdout.buffer.write(b'trusted')\n"
        )
        malicious_marker = self.root / "replacement-at-handoff.marker"
        replacement = self.make_executable(
            "import pathlib, sys\n"
            f"pathlib.Path({str(malicious_marker)!r}).write_text('ran')\n"
            "sys.stdout.buffer.write(b'malicious')\n"
        )
        preflight = self.preflight_result_path(accepted)
        expected_preflight_digest = hashlib.sha256(preflight.read_bytes()).hexdigest()
        stdout = self.root / "snapshot-binding.out"
        stderr = self.root / "snapshot-binding.err"
        original_backup = self.root / "snapshot-binding.original"
        original_capture = named_lane_runtime.run_bounded_capture
        replaced = False

        def replace_at_handoff(argv: object, **kwargs: object) -> object:
            nonlocal replaced
            command = tuple(str(item) for item in argv)
            if not replaced and pathlib.Path(command[0]).name.startswith(
                ".named-lane-"
            ):
                accepted.rename(original_backup)
                os.replace(replacement, accepted)
                try:
                    return original_capture(command, **kwargs)
                finally:
                    os.replace(original_backup, accepted)
                    replaced = True
            return original_capture(command, **kwargs)

        with mock.patch.object(
            named_lane_runtime,
            "run_bounded_capture",
            side_effect=replace_at_handoff,
        ):
            result = self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=stdout,
                stderr_path=stderr,
                command=(str(accepted),),
                preflight_result=preflight,
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=64,
            )

        self.assertTrue(replaced)
        self.assertEqual(stdout.read_bytes(), b"trusted")
        self.assertFalse(malicious_marker.exists())
        self.assertEqual(
            result["launch_binding"]["preflight_sha256"],
            expected_preflight_digest,
        )
        self.assertEqual(result["launch_binding"]["resolved_path"], str(accepted))
        self.assertEqual(tuple(self.root.glob(".named-lane-*")), ())

    def test_process_ignores_nonsemantic_executable_timestamp_and_link_churn(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable(
            "import sys\nsys.stdout.buffer.write(b'bound')\n"
        )
        metadata = executable.stat()
        os.utime(
            executable,
            ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000),
        )
        extra_link = self.root / "benign-executable-hardlink"
        os.link(executable, extra_link)
        try:
            result = self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "benign-metadata.out",
                stderr_path=self.root / "benign-metadata.err",
                command=(str(executable),),
                preflight_result=self.preflight_result_path(executable),
                prompt=b"",
                timeout_seconds=5.0,
                stream_limit_bytes=64,
            )
        finally:
            extra_link.unlink(missing_ok=True)

        self.assertEqual(result["status"], "complete")
        self.assertEqual((self.root / "benign-metadata.out").read_bytes(), b"bound")

    def test_process_rejects_a_forged_preflight_artifact_checksum(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("raise SystemExit(97)\n")
        preflight = self.preflight_result_path(executable)
        evidence = json.loads(preflight.read_text(encoding="utf-8"))
        evidence["publisher_verification"]["checksum"] = "0" * 64
        preflight.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
        preflight.chmod(0o600)

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "changed during launch binding",
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "forged-checksum.out",
                stderr_path=self.root / "forged-checksum.err",
                command=(str(executable),),
                preflight_result=preflight,
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=64,
            )

        self.assertEqual(tuple(self.root.glob(".named-lane-*")), ())

    def test_process_rejects_same_inode_executable_content_drift(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable(
            "import sys\nsys.stdout.buffer.write(b'trusted')\n"
        )
        payload = bytearray(executable.read_bytes())
        payload[-3] = ord("X")
        executable.write_bytes(payload)
        executable.chmod(0o755)

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "changed during launch binding",
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "same-inode-drift.out",
                stderr_path=self.root / "same-inode-drift.err",
                command=(str(executable),),
                preflight_result=self.preflight_result_path(executable),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=64,
            )

        self.assertEqual(tuple(self.root.glob(".named-lane-*")), ())

    def test_process_requires_parent_private_preflight_evidence(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("pass\n")
        preflight = self.preflight_result_path(executable)
        symlink = self.root / "preflight-symlink.json"
        symlink.symlink_to(preflight)
        hardlink = self.root / "preflight-hardlink.json"
        os.link(preflight, hardlink)
        try:
            for label, candidate, expected in (
                ("relative", pathlib.Path(preflight.name), "must be absolute"),
                ("symlink", symlink, "single-link regular file"),
                ("hardlink", hardlink, "single-link regular file"),
            ):
                with self.subTest(label=label):
                    with self.assertRaisesRegex(NamedLaneGuardError, expected):
                        self.run_claude(
                            worktree=self.repo.resolve(),
                            stdout_path=self.root / f"{label}-preflight.out",
                            stderr_path=self.root / f"{label}-preflight.err",
                            command=(str(executable),),
                            preflight_result=candidate,
                            prompt=b"",
                            timeout_seconds=2.0,
                            stream_limit_bytes=64,
                        )
        finally:
            hardlink.unlink(missing_ok=True)

        preflight.chmod(0o644)
        try:
            with self.assertRaisesRegex(
                NamedLaneGuardError,
                "private single-link regular file",
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=self.root / "permissive-preflight.out",
                    stderr_path=self.root / "permissive-preflight.err",
                    command=(str(executable),),
                    preflight_result=preflight,
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=64,
                )
        finally:
            preflight.chmod(0o600)

    def test_initial_launch_snapshot_fstat_failure_removes_snapshot(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("pass\n")
        real_fstat = os.fstat
        failed_once = False

        def fail_snapshot_fstat(descriptor: int) -> os.stat_result:
            nonlocal failed_once
            launch_snapshots = tuple(self.root.glob(".named-lane-launch-*"))
            if not failed_once and launch_snapshots:
                failed_once = True
                raise OSError("synthetic launch snapshot fstat failure")
            return real_fstat(descriptor)

        with (
            mock.patch.object(
                named_lane_runtime.os,
                "fstat",
                side_effect=fail_snapshot_fstat,
            ),
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "launch snapshot cannot be inspected safely",
            ),
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "snapshot-fstat.out",
                stderr_path=self.root / "snapshot-fstat.err",
                command=(str(executable),),
                preflight_result=self.preflight_result_path(executable),
                prompt=b"",
                timeout_seconds=5.0,
                stream_limit_bytes=64,
            )

        self.assertTrue(failed_once)
        self.assertEqual(tuple(self.root.glob(".named-lane-*")), ())

    def test_persistent_launch_snapshot_fstat_failure_reports_retained_path(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("pass\n")
        real_fstat = os.fstat

        def fail_snapshot_fstat(descriptor: int) -> os.stat_result:
            if tuple(self.root.glob(".named-lane-launch-*")):
                raise OSError("synthetic persistent launch snapshot fstat failure")
            return real_fstat(descriptor)

        retained: pathlib.Path | None = None
        try:
            with (
                mock.patch.object(
                    named_lane_runtime.os,
                    "fstat",
                    side_effect=fail_snapshot_fstat,
                ),
                self.assertRaisesRegex(
                    NamedLaneGuardError,
                    "cleanup cannot bind the retained path",
                ) as context,
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=self.root / "persistent-snapshot-fstat.out",
                    stderr_path=self.root / "persistent-snapshot-fstat.err",
                    command=(str(executable),),
                    preflight_result=self.preflight_result_path(executable),
                    prompt=b"",
                    timeout_seconds=5.0,
                    stream_limit_bytes=64,
                )
            retained_paths = tuple(self.root.glob(".named-lane-launch-*"))
            self.assertEqual(len(retained_paths), 1)
            retained = retained_paths[0]
            self.assertIn(str(retained), str(context.exception))
        finally:
            if retained is not None:
                retained.unlink(missing_ok=True)

    def test_launch_snapshot_rehash_obeys_the_shared_deadline(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("pass\n")
        real_remaining = named_lane_runtime._remaining_deadline_seconds
        snapshot_checks = 0

        def expire_during_rehash(deadline: float, label: str) -> float:
            nonlocal snapshot_checks
            if label == "Claude executable snapshot":
                snapshot_checks += 1
                if snapshot_checks == 3:
                    raise ReviewTimeoutError("synthetic rehash deadline")
            return real_remaining(deadline, label)

        with (
            mock.patch.object(
                named_lane_runtime,
                "_remaining_deadline_seconds",
                side_effect=expire_during_rehash,
            ),
            self.assertRaisesRegex(ReviewTimeoutError, "rehash deadline"),
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "rehash-deadline.out",
                stderr_path=self.root / "rehash-deadline.err",
                command=(str(executable),),
                preflight_result=self.preflight_result_path(executable),
                prompt=b"",
                timeout_seconds=5.0,
                stream_limit_bytes=64,
            )

        self.assertEqual(snapshot_checks, 3)
        self.assertEqual(tuple(self.root.glob(".named-lane-*")), ())

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "launch snapshot signal transaction requires POSIX pthread_sigmask",
    )
    def test_launch_snapshot_handoff_signal_removes_snapshot(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("pass\n")
        real_restore = named_lane_runtime.restore_signal_mask
        restore_calls = 0

        def interrupt_first_restore(previous: object) -> None:
            nonlocal restore_calls
            restore_calls += 1
            real_restore(previous)
            if restore_calls == 1:
                raise ForwardedSignal(signal.SIGTERM)

        with (
            mock.patch.object(
                named_lane_runtime,
                "restore_signal_mask",
                side_effect=interrupt_first_restore,
            ),
            self.assertRaises(ForwardedSignal),
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "snapshot-handoff.out",
                stderr_path=self.root / "snapshot-handoff.err",
                command=(str(executable),),
                preflight_result=self.preflight_result_path(executable),
                prompt=b"",
                timeout_seconds=5.0,
                stream_limit_bytes=64,
            )

        self.assertGreaterEqual(restore_calls, 2)
        self.assertEqual(tuple(self.root.glob(".named-lane-*")), ())

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "launch snapshot signal transaction requires POSIX pthread_sigmask",
    )
    def test_launch_snapshot_cleanup_defers_pending_signal_after_removal(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("print('captured')\n")
        real_restore = named_lane_runtime.restore_signal_mask
        restore_calls = 0

        def interrupt_cleanup_restore(previous: object) -> None:
            nonlocal restore_calls
            restore_calls += 1
            real_restore(previous)
            if restore_calls == 2:
                raise ForwardedSignal(signal.SIGINT)

        with (
            mock.patch.object(
                named_lane_runtime,
                "restore_signal_mask",
                side_effect=interrupt_cleanup_restore,
            ),
            self.assertRaises(ForwardedSignal) as context,
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "cleanup-signal.out",
                stderr_path=self.root / "cleanup-signal.err",
                command=(str(executable),),
                preflight_result=self.preflight_result_path(executable),
                prompt=b"",
                timeout_seconds=5.0,
                stream_limit_bytes=64,
            )

        self.assertEqual(context.exception.signum, signal.SIGINT)
        self.assertEqual(restore_calls, 2)
        self.assertEqual(tuple(self.root.glob(".named-lane-*")), ())
        self.assertFalse((self.root / "cleanup-signal.out").exists())
        self.assertFalse((self.root / "cleanup-signal.err").exists())

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "launch snapshot signal transaction requires POSIX pthread_sigmask",
    )
    def test_launch_snapshot_cleanup_failure_records_pending_signal_reason(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("pass\n")
        real_restore = named_lane_runtime.restore_signal_mask
        restore_calls = 0
        retained: pathlib.Path | None = None

        def interrupt_cleanup_restore(previous: object) -> None:
            nonlocal restore_calls
            restore_calls += 1
            real_restore(previous)
            if restore_calls == 2:
                raise ForwardedSignal(signal.SIGTERM)

        def fail_cleanup(snapshot: object, _target: object) -> None:
            nonlocal retained
            retained = snapshot.path
            raise OSError("synthetic snapshot cleanup failure")

        try:
            with (
                mock.patch.object(
                    named_lane_runtime,
                    "restore_signal_mask",
                    side_effect=interrupt_cleanup_restore,
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "_cleanup_claude_launch_snapshot",
                    side_effect=fail_cleanup,
                ),
                self.assertRaises(
                    named_lane_runtime._ClaudeLaunchSnapshotCleanupError
                ) as context,
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=self.root / "cleanup-signal-failure.out",
                    stderr_path=self.root / "cleanup-signal-failure.err",
                    command=(str(executable),),
                    preflight_result=self.preflight_result_path(executable),
                    prompt=b"",
                    timeout_seconds=5.0,
                    stream_limit_bytes=64,
                )
            self.assertEqual(context.exception.process_reason, "forwarded-signal")
            self.assertEqual(context.exception.retained_path, retained)
            self.assertIsNotNone(retained)
            self.assertTrue(retained.exists())
        finally:
            if retained is not None:
                retained.unlink(missing_ok=True)

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "launch snapshot signal transaction requires POSIX pthread_sigmask",
    )
    def test_launch_snapshot_cleanup_mask_restore_retries_and_clears_capture(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("print('captured')\n")
        real_restore = named_lane_runtime.restore_signal_mask
        real_capture = named_lane_runtime.run_bounded_capture
        restore_calls = 0
        process_capture: object | None = None
        initial_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())

        def fail_cleanup_restores(previous: object) -> None:
            nonlocal restore_calls
            restore_calls += 1
            if restore_calls == 1:
                real_restore(previous)
            else:
                raise OSError("synthetic persistent mask restore failure")

        def retain_process_capture(argv: object, **kwargs: object) -> object:
            nonlocal process_capture
            result = real_capture(argv, **kwargs)
            if str(tuple(argv)[0]).startswith(str(self.root / ".named-lane-launch-")):
                process_capture = result
            return result

        mask_after_failure: set[signal.Signals] | None = None
        try:
            with (
                mock.patch.object(
                    named_lane_runtime,
                    "restore_signal_mask",
                    side_effect=fail_cleanup_restores,
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "run_bounded_capture",
                    side_effect=retain_process_capture,
                ),
                self.assertRaisesRegex(
                    NamedLaneGuardError,
                    "signal mask could not be restored",
                ),
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=self.root / "cleanup-mask.out",
                    stderr_path=self.root / "cleanup-mask.err",
                    command=(str(executable),),
                    preflight_result=self.preflight_result_path(executable),
                    prompt=b"",
                    timeout_seconds=5.0,
                    stream_limit_bytes=64,
                )
        finally:
            mask_after_failure = signal.pthread_sigmask(signal.SIG_BLOCK, set())
            real_restore(initial_mask)

        self.assertEqual(restore_calls, 3)
        self.assertTrue(
            set(named_lane_runtime.forwarded_signals()).issubset(mask_after_failure)
        )
        self.assertEqual(
            signal.pthread_sigmask(signal.SIG_BLOCK, set()),
            initial_mask,
        )
        self.assertIsNotNone(process_capture)
        self.assertGreater(len(process_capture.stdout), 0)
        self.assertFalse(any(process_capture.stdout))
        self.assertFalse(any(process_capture.stderr))
        self.assertEqual(tuple(self.root.glob(".named-lane-*")), ())
        self.assertFalse((self.root / "cleanup-mask.out").exists())
        self.assertFalse((self.root / "cleanup-mask.err").exists())

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "launch snapshot signal transaction requires POSIX pthread_sigmask",
    )
    def test_launch_snapshot_cleanup_mask_restore_retries_true_oserror(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("print('captured')\n")
        real_restore = named_lane_runtime.restore_signal_mask
        restore_calls = 0

        def fail_first_cleanup_restore(previous: object) -> None:
            nonlocal restore_calls
            restore_calls += 1
            if restore_calls == 2:
                raise OSError("synthetic first mask restore failure")
            real_restore(previous)

        with mock.patch.object(
            named_lane_runtime,
            "restore_signal_mask",
            side_effect=fail_first_cleanup_restore,
        ):
            result = self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "cleanup-mask-retry.out",
                stderr_path=self.root / "cleanup-mask-retry.err",
                command=(str(executable),),
                preflight_result=self.preflight_result_path(executable),
                prompt=b"",
                timeout_seconds=5.0,
                stream_limit_bytes=64,
            )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(restore_calls, 5)
        self.assertEqual(
            (self.root / "cleanup-mask-retry.out").read_text(encoding="utf-8"),
            "captured\n",
        )
        self.assertEqual(tuple(self.root.glob(".named-lane-*")), ())

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "launch snapshot signal transaction requires POSIX pthread_sigmask",
    )
    def test_launch_snapshot_cleanup_mask_restore_preserves_control_flow(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("print('captured')\n")
        real_restore = named_lane_runtime.restore_signal_mask

        for label, control_error in (
            ("keyboard", KeyboardInterrupt()),
            ("system-exit", SystemExit(23)),
        ):
            with self.subTest(label=label):
                restore_calls = 0

                def interrupt_cleanup_restore(previous: object) -> None:
                    nonlocal restore_calls
                    restore_calls += 1
                    real_restore(previous)
                    if restore_calls == 2:
                        raise control_error

                with (
                    mock.patch.object(
                        named_lane_runtime,
                        "restore_signal_mask",
                        side_effect=interrupt_cleanup_restore,
                    ),
                    self.assertRaises(type(control_error)) as context,
                ):
                    self.run_claude(
                        worktree=self.repo.resolve(),
                        stdout_path=self.root / f"cleanup-{label}.out",
                        stderr_path=self.root / f"cleanup-{label}.err",
                        command=(str(executable),),
                        preflight_result=self.preflight_result_path(executable),
                        prompt=b"",
                        timeout_seconds=5.0,
                        stream_limit_bytes=64,
                    )

                self.assertIs(context.exception, control_error)
                self.assertEqual(restore_calls, 3)
                self.assertEqual(tuple(self.root.glob(".named-lane-*")), ())
                self.assertFalse((self.root / f"cleanup-{label}.out").exists())
                self.assertFalse((self.root / f"cleanup-{label}.err").exists())

    def test_post_run_snapshot_cleanup_failure_reports_complete_and_path(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("pass\n")
        retained: pathlib.Path | None = None

        def fail_cleanup(
            snapshot: object,
            _target: object,
        ) -> None:
            nonlocal retained
            retained = snapshot.path
            raise OSError("synthetic snapshot cleanup failure")

        try:
            with (
                mock.patch.object(
                    named_lane_runtime,
                    "_cleanup_claude_launch_snapshot",
                    side_effect=fail_cleanup,
                ),
                self.assertRaises(
                    named_lane_runtime._ClaudeLaunchSnapshotCleanupError
                ) as context,
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=self.root / "cleanup-complete.out",
                    stderr_path=self.root / "cleanup-complete.err",
                    command=(str(executable),),
                    preflight_result=self.preflight_result_path(executable),
                    prompt=b"",
                    timeout_seconds=5.0,
                    stream_limit_bytes=64,
                )
            self.assertEqual(context.exception.process_reason, "complete")
            self.assertEqual(context.exception.retained_path, retained)
            self.assertIsNotNone(retained)
            self.assertTrue(retained.exists())
            self.assertIn(str(retained), str(context.exception))
            self.assertFalse((self.root / "cleanup-complete.out").exists())
            self.assertFalse((self.root / "cleanup-complete.err").exists())
        finally:
            if retained is not None:
                retained.unlink(missing_ok=True)

    def test_post_run_snapshot_cleanup_failure_preserves_deadline_reason(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable(
            "import time\nwhile True:\n    time.sleep(0.05)\n"
        )
        real_capture = named_lane_runtime.run_bounded_capture
        retained: pathlib.Path | None = None

        def timeout_process_capture(argv: object, **kwargs: object) -> object:
            if str(tuple(argv)[0]).startswith(str(self.root / ".named-lane-launch-")):
                raise ReviewTimeoutError("synthetic Claude process deadline")
            return real_capture(argv, **kwargs)

        def fail_cleanup(
            snapshot: object,
            _target: object,
        ) -> None:
            nonlocal retained
            retained = snapshot.path
            raise OSError("synthetic snapshot cleanup failure")

        try:
            with (
                mock.patch.object(
                    named_lane_runtime,
                    "_cleanup_claude_launch_snapshot",
                    side_effect=fail_cleanup,
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "run_bounded_capture",
                    side_effect=timeout_process_capture,
                ),
                self.assertRaises(
                    named_lane_runtime._ClaudeLaunchSnapshotCleanupError
                ) as context,
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=self.root / "cleanup-deadline.out",
                    stderr_path=self.root / "cleanup-deadline.err",
                    command=(str(executable),),
                    preflight_result=self.preflight_result_path(executable),
                    prompt=b"",
                    timeout_seconds=5.0,
                    stream_limit_bytes=64,
                )
            self.assertEqual(context.exception.process_reason, "deadline")
            self.assertEqual(context.exception.retained_path, retained)
            self.assertIsNotNone(retained)
            self.assertTrue(retained.exists())
        finally:
            if retained is not None:
                retained.unlink(missing_ok=True)

    @unittest.skipUnless(os.name == "posix", "account environment requires POSIX")
    def test_process_receives_only_the_named_lane_environment_allowlist(
        self,
    ) -> None:
        import pwd

        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable(
            "import json, os, sys\n"
            "json.dump(dict(os.environ), sys.stdout, sort_keys=True)\n"
        )
        stdout = self.root / "environment.json"
        stderr = self.root / "environment.err"
        default_stdout = self.root / "environment-default.json"
        default_stderr = self.root / "environment-default.err"
        allowed = {
            "LANG": "en_US.UTF-8",
            "TERM": "xterm-256color",
            "https_proxy": "http://proxy.example.invalid:8080",
            "REQUESTS_CA_BUNDLE": "/etc/example-ca.pem",
        }
        denied = {
            "ANTHROPIC_API_KEY": "secret",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "0",
            "CLAUDE_CODE_OAUTH_TOKEN": "secret",
            "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "0",
            "CLAUDE_CONFIG_DIR": "/private/claude",
            "GITHUB_TOKEN": "secret",
            "GH_TOKEN": "secret",
            "AWS_SECRET_ACCESS_KEY": "secret",
            "NODE_OPTIONS": "--require=/private/hook.js",
            "NODE_EXTRA_CA_CERTS": "/private/node-ca.pem",
            "LD_PRELOAD": "/private/preload.so",
            "DYLD_INSERT_LIBRARIES": "/private/inject.dylib",
            "TMPDIR": "/private/tmpdir",
            "XDG_CONFIG_HOME": "/private/config",
        }
        node_extra_ca = self.root / "node-extra-ca.pem"
        node_extra_ca.write_text(
            "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n",
            encoding="ascii",
        )
        denied["NODE_EXTRA_CA_CERTS"] = str(node_extra_ca)
        with mock.patch.dict(os.environ, {**allowed, **denied}, clear=True):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=default_stdout,
                stderr_path=default_stderr,
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=stdout,
                stderr_path=stderr,
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
                inherit_node_extra_ca_certs=True,
            )

        child = json.loads(stdout.read_text(encoding="utf-8"))
        default_child = json.loads(default_stdout.read_text(encoding="utf-8"))
        account = pwd.getpwuid(os.getuid())
        for key, value in allowed.items():
            self.assertEqual(child[key], value)
        self.assertEqual(child["HOME"], account.pw_dir)
        self.assertEqual(child["USER"], account.pw_name)
        self.assertEqual(child["LOGNAME"], account.pw_name)
        self.assertEqual(child["SHELL"], account.pw_shell)
        self.assertEqual(child["PATH"], TRUSTED_PATH)
        self.assertEqual(
            child["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"],
            "1",
        )
        self.assertEqual(
            default_child["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"],
            "1",
        )
        self.assertNotIn("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB", child)
        self.assertNotIn("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB", default_child)
        for key in denied.keys() - {
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
            "NODE_EXTRA_CA_CERTS",
        }:
            self.assertNotIn(key, child)
        self.assertNotIn("NODE_EXTRA_CA_CERTS", default_child)
        self.assertEqual(child["NODE_EXTRA_CA_CERTS"], str(node_extra_ca))
        self.assertEqual(child["GIT_LITERAL_PATHSPECS"], "1")
        self.assertEqual(child["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(child["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(child["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(child["GIT_GRAFT_FILE"], os.devnull)
        self.assertEqual(child["GIT_OPTIONAL_LOCKS"], "0")
        self.assertEqual(child["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(child["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(child["GIT_CONFIG_SYSTEM"], os.devnull)
        self.assertEqual(
            child["GIT_CEILING_DIRECTORIES"],
            str(self.repo.resolve().parent),
        )
        self.assertEqual(child["GIT_ASKPASS"], "/usr/bin/false")
        self.assertEqual(child["GIT_ATTR_NOSYSTEM"], "1")
        self.assertEqual(child["GIT_PAGER"], "cat")
        self.assertEqual(child["PAGER"], "cat")
        self.assertNotIn("GIT_ALLOW_PROTOCOL", child)

    @unittest.skipUnless(os.name == "posix", "session environment requires POSIX")
    def test_claude_2_1_226_receives_a_prepared_guard_managed_session(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        executable = self.make_executable(
            "import fcntl, json, os, pathlib, sys\n"
            "arguments = sys.argv[1:]\n"
            "index = arguments.index('--session-id')\n"
            "session_id = arguments[index + 1]\n"
            "leaf = pathlib.Path(os.environ['HOME']) / '.claude' / "
            "'session-env' / session_id\n"
            "leaf.mkdir(exist_ok=True)\n"
            "anchor_fd = os.open(leaf.parents[1], os.O_RDONLY)\n"
            "try:\n"
            "    fcntl.flock(anchor_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
            "except BlockingIOError:\n"
            "    namespace_lock_blocked = True\n"
            "else:\n"
            "    namespace_lock_blocked = False\n"
            "    fcntl.flock(anchor_fd, fcntl.LOCK_UN)\n"
            "finally:\n"
            "    os.close(anchor_fd)\n"
            "json.dump({'arguments': arguments, 'session_id': session_id, 'mode': "
            "leaf.stat().st_mode & 0o777, 'namespace_lock_blocked': "
            "namespace_lock_blocked}, sys.stdout)\n",
            version="2.1.226",
        )
        stdout = self.root / "session-env.json"
        stderr = self.root / "session-env.err"
        with mock.patch("pwd.getpwuid", return_value=self.claude_account(home)):
            result = self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=stdout,
                stderr_path=stderr,
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )

        observed = json.loads(stdout.read_text(encoding="utf-8"))
        self.assertEqual(result["status"], "complete")
        self.assertEqual(
            result["launch_binding"]["session_id"],
            observed["session_id"],
        )
        session_binding = result["launch_binding"]["session_env"]
        self.assertEqual(
            session_binding["identity_binding"],
            "first-no-follow-open-after-exclusive-mkdir",
        )
        self.assertFalse(session_binding["creation_origin_proven"])
        self.assertEqual(
            session_binding["creation_origin_guarantee"],
            "best-effort-122-bit-uuidv4-leaf-immediate-nofollow-open-"
            "cooperative-claude-control-directory-flock-same-uid-host-tcb",
        )
        self.assertEqual(
            session_binding["namespace_exclusivity_guarantee"],
            "exclusive-advisory-claude-control-directory-flock-"
            "cooperative-same-uid-host-tcb",
        )
        self.assertEqual(
            session_binding["cleanup_guarantee"],
            "descriptor-custody-emptiness-revalidation-nonrecursive-rmdir-"
            "cooperative-claude-control-directory-flock-same-uid-host-tcb",
        )
        self.assertEqual(
            session_binding["cleanup_observation"],
            "selected-name-absent-after-rmdir",
        )
        self.assertEqual(
            session_binding["namespace_identity"]["file_type"],
            stat.S_IFDIR,
        )
        self.assertEqual(session_binding["parent_identity"]["file_type"], stat.S_IFDIR)
        self.assertEqual(session_binding["leaf_identity"]["file_type"], stat.S_IFDIR)
        self.assertEqual(session_binding["leaf_identity"]["uid"], os.geteuid())
        self.assertRegex(
            observed["session_id"],
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        )
        self.assertEqual(observed["mode"], 0o700)
        self.assertTrue(observed["namespace_lock_blocked"])
        self.assertEqual(list((home / ".claude" / "session-env").iterdir()), [])
        profile = result["launch_binding"]["argv_profile"]
        self.assertEqual(
            observed["arguments"],
            [
                "--session-id",
                observed["session_id"],
                *profile["guard_constructed_arguments"],
            ],
        )
        self.assertEqual(profile["effective_arguments"], observed["arguments"])
        self.assertNotIn("--session-id", profile["guard_constructed_arguments"])
        canonical = named_lane_runtime._canonical_json_bytes
        self.assertEqual(
            profile["effective_arguments_sha256"],
            hashlib.sha256(canonical(observed["arguments"])).hexdigest(),
        )
        payload = dict(profile)
        digest = payload.pop("profile_sha256")
        self.assertEqual(digest, hashlib.sha256(canonical(payload)).hexdigest())

    @unittest.skipUnless(os.name == "posix", "session environment requires POSIX")
    def test_claude_session_namespace_lease_failure_blocks_launch(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        marker = self.root / "namespace-lease-launch-marker"
        executable = self.make_executable(
            f"import pathlib\npathlib.Path({str(marker)!r}).touch()\n",
            version="2.1.226",
        )

        with (
            mock.patch("pwd.getpwuid", return_value=self.claude_account(home)),
            mock.patch.object(
                named_lane_runtime.fcntl,
                "flock",
                side_effect=BlockingIOError("synthetic busy namespace lease"),
            ),
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "namespace lease is already held",
            ),
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "namespace-lease.out",
                stderr_path=self.root / "namespace-lease.err",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )

        self.assertFalse(marker.exists())
        self.assertFalse((self.root / "namespace-lease.out").exists())
        self.assertFalse((self.root / "namespace-lease.err").exists())
        self.assertEqual(list((home / ".claude" / "session-env").iterdir()), [])
        self.assertEqual(tuple(self.root.glob(".named-lane-launch-*")), ())

    @unittest.skipUnless(os.name == "posix", "session environment requires POSIX")
    def test_session_env_receipt_does_not_claim_mkdir_origin(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        parent = home / ".claude" / "session-env"
        session_id = "00000000-0000-4000-8000-000000000226"
        displaced = parent / f"{session_id}-mkdir-created"
        replacement_identity: tuple[int, int] | None = None
        mkdir_created_identity: tuple[int, int] | None = None
        real_mkdir = named_lane_runtime.os.mkdir
        replaced = False
        executable = self.make_executable(
            "import os, pathlib, sys\n"
            "arguments = sys.argv[1:]\n"
            "session_id = arguments[arguments.index('--session-id') + 1]\n"
            "leaf = pathlib.Path(os.environ['HOME']) / '.claude' / "
            "'session-env' / session_id\n"
            "leaf.mkdir(exist_ok=True)\n",
            version="2.1.226",
        )

        def replace_after_leaf_mkdir(
            path: object,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal mkdir_created_identity, replaced, replacement_identity
            real_mkdir(path, mode=mode, dir_fd=dir_fd)
            if replaced or path != session_id or dir_fd is None:
                return
            replaced = True
            created = parent / session_id
            created_metadata = created.stat()
            mkdir_created_identity = (
                created_metadata.st_dev,
                created_metadata.st_ino,
            )
            created.rename(displaced)
            real_mkdir(session_id, mode=0o700, dir_fd=dir_fd)
            replacement_metadata = (parent / session_id).stat()
            replacement_identity = (
                replacement_metadata.st_dev,
                replacement_metadata.st_ino,
            )

        try:
            with (
                mock.patch(
                    "pwd.getpwuid",
                    return_value=self.claude_account(home),
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "_new_claude_session_id",
                    return_value=session_id,
                ),
                mock.patch.object(
                    named_lane_runtime.os,
                    "mkdir",
                    side_effect=replace_after_leaf_mkdir,
                ),
            ):
                result = self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=self.root / "mkdir-origin.out",
                    stderr_path=self.root / "mkdir-origin.err",
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=16 * 1024,
                )

            self.assertTrue(replaced)
            self.assertIsNotNone(mkdir_created_identity)
            self.assertIsNotNone(replacement_identity)
            self.assertNotEqual(mkdir_created_identity, replacement_identity)
            session_binding = result["launch_binding"]["session_env"]
            self.assertFalse(session_binding["creation_origin_proven"])
            self.assertEqual(
                (
                    session_binding["leaf_identity"]["device"],
                    session_binding["leaf_identity"]["inode"],
                ),
                replacement_identity,
            )
            self.assertTrue(displaced.is_dir())
            self.assertFalse((parent / session_id).exists())
        finally:
            if (parent / session_id).exists():
                (parent / session_id).rmdir()
            if displaced.exists():
                displaced.rmdir()

    @unittest.skipUnless(os.name == "posix", "session environment requires POSIX")
    def test_session_env_replacement_during_snapshot_blocks_handoff(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        parent = home / ".claude" / "session-env"
        marker = self.root / "snapshot-replacement-launch-marker"
        executable = self.make_executable(
            f"import pathlib\npathlib.Path({str(marker)!r}).touch()\n",
            version="2.1.226",
        )
        real_create_snapshot = named_lane_runtime._create_claude_launch_snapshot
        real_capture = named_lane_runtime.run_bounded_capture
        launch_commands: list[tuple[object, ...]] = []
        displaced: pathlib.Path | None = None
        replacement: pathlib.Path | None = None
        original_identity: tuple[int, int] | None = None

        def create_snapshot_then_replace(*args: object, **kwargs: object) -> object:
            nonlocal displaced, original_identity, replacement
            snapshot = real_create_snapshot(*args, **kwargs)
            leaves = tuple(parent.iterdir())
            self.assertEqual(len(leaves), 1)
            leaf = leaves[0]
            metadata = leaf.stat()
            original_identity = (metadata.st_dev, metadata.st_ino)
            displaced = parent / f"{leaf.name}-snapshot-bound"
            leaf.rename(displaced)
            leaf.mkdir(mode=0o700)
            leaf.chmod(0o700)
            replacement = leaf
            return snapshot

        def record_launch(argv: object, **kwargs: object) -> object:
            arguments = tuple(argv)
            if str(arguments[0]).startswith(str(self.root / ".named-lane-launch-")):
                launch_commands.append(arguments)
                raise AssertionError(
                    "Claude launch must not follow session replacement"
                )
            return real_capture(argv, **kwargs)

        try:
            with (
                mock.patch(
                    "pwd.getpwuid",
                    return_value=self.claude_account(home),
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "_create_claude_launch_snapshot",
                    side_effect=create_snapshot_then_replace,
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "run_bounded_capture",
                    side_effect=record_launch,
                ),
                self.assertRaises(
                    named_lane_runtime._ClaudeSessionEnvCleanupError
                ) as context,
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=self.root / "snapshot-replacement.out",
                    stderr_path=self.root / "snapshot-replacement.err",
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=16 * 1024,
                )

            error = context.exception
            self.assertEqual(launch_commands, [])
            self.assertFalse(marker.exists())
            self.assertIsNone(error.retained_path)
            self.assertEqual(error.retained_leaf_identity, original_identity)
            self.assertIsNotNone(displaced)
            self.assertIsNotNone(replacement)
            assert displaced is not None
            assert replacement is not None
            self.assertTrue(displaced.is_dir())
            self.assertTrue(replacement.is_dir())
            self.assertFalse((self.root / "snapshot-replacement.out").exists())
            self.assertFalse((self.root / "snapshot-replacement.err").exists())
            self.assertEqual(tuple(self.root.glob(".named-lane-launch-*")), ())
        finally:
            if replacement is not None and replacement.exists():
                replacement.rmdir()
            if displaced is not None and displaced.exists():
                displaced.rmdir()

    @unittest.skipUnless(os.name == "posix", "session environment requires POSIX")
    def test_session_env_mode_tightening_during_snapshot_blocks_handoff(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        parent = home / ".claude" / "session-env"
        marker = self.root / "snapshot-mode-launch-marker"
        executable = self.make_executable(
            f"import pathlib\npathlib.Path({str(marker)!r}).touch()\n",
            version="2.1.226",
        )
        real_create_snapshot = named_lane_runtime._create_claude_launch_snapshot
        real_capture = named_lane_runtime.run_bounded_capture
        launch_commands: list[tuple[object, ...]] = []

        def create_snapshot_then_tighten(*args: object, **kwargs: object) -> object:
            snapshot = real_create_snapshot(*args, **kwargs)
            leaves = tuple(parent.iterdir())
            self.assertEqual(len(leaves), 1)
            leaves[0].chmod(0o600)
            return snapshot

        def record_launch(argv: object, **kwargs: object) -> object:
            arguments = tuple(argv)
            if str(arguments[0]).startswith(str(self.root / ".named-lane-launch-")):
                launch_commands.append(arguments)
                raise AssertionError("Claude launch must not follow mode drift")
            return real_capture(argv, **kwargs)

        with (
            mock.patch("pwd.getpwuid", return_value=self.claude_account(home)),
            mock.patch.object(
                named_lane_runtime,
                "_create_claude_launch_snapshot",
                side_effect=create_snapshot_then_tighten,
            ),
            mock.patch.object(
                named_lane_runtime,
                "run_bounded_capture",
                side_effect=record_launch,
            ),
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "leaf handoff mode changed",
            ),
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "snapshot-mode.out",
                stderr_path=self.root / "snapshot-mode.err",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )

        self.assertEqual(launch_commands, [])
        self.assertFalse(marker.exists())
        self.assertEqual(list(parent.iterdir()), [])
        self.assertFalse((self.root / "snapshot-mode.out").exists())
        self.assertFalse((self.root / "snapshot-mode.err").exists())
        self.assertEqual(tuple(self.root.glob(".named-lane-launch-*")), ())

    @unittest.skipUnless(os.name == "posix", "session environment requires POSIX")
    def test_session_env_content_during_snapshot_blocks_handoff(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        parent = home / ".claude" / "session-env"
        marker = self.root / "snapshot-content-launch-marker"
        executable = self.make_executable(
            f"import pathlib\npathlib.Path({str(marker)!r}).touch()\n",
            version="2.1.226",
        )
        real_create_snapshot = named_lane_runtime._create_claude_launch_snapshot
        real_capture = named_lane_runtime.run_bounded_capture
        launch_commands: list[tuple[object, ...]] = []
        retained_leaf: pathlib.Path | None = None

        def create_snapshot_then_add_content(
            *args: object,
            **kwargs: object,
        ) -> object:
            nonlocal retained_leaf
            snapshot = real_create_snapshot(*args, **kwargs)
            leaves = tuple(parent.iterdir())
            self.assertEqual(len(leaves), 1)
            retained_leaf = leaves[0]
            (retained_leaf / "unexpected").write_text(
                "retained",
                encoding="utf-8",
            )
            return snapshot

        def record_launch(argv: object, **kwargs: object) -> object:
            arguments = tuple(argv)
            if str(arguments[0]).startswith(str(self.root / ".named-lane-launch-")):
                launch_commands.append(arguments)
                raise AssertionError("Claude launch must not follow content drift")
            return real_capture(argv, **kwargs)

        try:
            with (
                mock.patch(
                    "pwd.getpwuid",
                    return_value=self.claude_account(home),
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "_create_claude_launch_snapshot",
                    side_effect=create_snapshot_then_add_content,
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "run_bounded_capture",
                    side_effect=record_launch,
                ),
                self.assertRaises(
                    named_lane_runtime._ClaudeSessionEnvCleanupError
                ) as context,
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=self.root / "snapshot-content.out",
                    stderr_path=self.root / "snapshot-content.err",
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=16 * 1024,
                )

            self.assertEqual(launch_commands, [])
            self.assertFalse(marker.exists())
            self.assertEqual(context.exception.retained_path, retained_leaf)
            assert retained_leaf is not None
            self.assertEqual(
                (retained_leaf / "unexpected").read_text(encoding="utf-8"),
                "retained",
            )
            self.assertFalse((self.root / "snapshot-content.out").exists())
            self.assertFalse((self.root / "snapshot-content.err").exists())
            self.assertEqual(tuple(self.root.glob(".named-lane-launch-*")), ())
        finally:
            if retained_leaf is not None and retained_leaf.exists():
                unexpected = retained_leaf / "unexpected"
                if unexpected.exists():
                    unexpected.unlink()
                retained_leaf.rmdir()

    @unittest.skipUnless(os.name == "posix", "session environment requires POSIX")
    def test_session_env_parent_replacement_during_snapshot_blocks_handoff(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        parent = home / ".claude" / "session-env"
        displaced = home / ".claude" / "session-env-snapshot-bound"
        marker = self.root / "snapshot-parent-launch-marker"
        executable = self.make_executable(
            f"import pathlib\npathlib.Path({str(marker)!r}).touch()\n",
            version="2.1.226",
        )
        real_create_snapshot = named_lane_runtime._create_claude_launch_snapshot
        real_capture = named_lane_runtime.run_bounded_capture
        launch_commands: list[tuple[object, ...]] = []

        def create_snapshot_then_replace_parent(
            *args: object,
            **kwargs: object,
        ) -> object:
            snapshot = real_create_snapshot(*args, **kwargs)
            parent.rename(displaced)
            parent.mkdir(mode=0o700)
            parent.chmod(0o700)
            return snapshot

        def record_launch(argv: object, **kwargs: object) -> object:
            arguments = tuple(argv)
            if str(arguments[0]).startswith(str(self.root / ".named-lane-launch-")):
                launch_commands.append(arguments)
                raise AssertionError("Claude launch must not follow parent drift")
            return real_capture(argv, **kwargs)

        try:
            with (
                mock.patch(
                    "pwd.getpwuid",
                    return_value=self.claude_account(home),
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "_create_claude_launch_snapshot",
                    side_effect=create_snapshot_then_replace_parent,
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "run_bounded_capture",
                    side_effect=record_launch,
                ),
                self.assertRaises(
                    named_lane_runtime._ClaudeSessionEnvCustodyError
                ) as context,
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=self.root / "snapshot-parent.out",
                    stderr_path=self.root / "snapshot-parent.err",
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=16 * 1024,
                )

            self.assertEqual(launch_commands, [])
            self.assertFalse(marker.exists())
            self.assertEqual(context.exception.cleanup_status, "removed")
            self.assertEqual(list(displaced.iterdir()), [])
            self.assertEqual(list(parent.iterdir()), [])
            self.assertFalse((self.root / "snapshot-parent.out").exists())
            self.assertFalse((self.root / "snapshot-parent.err").exists())
            self.assertEqual(tuple(self.root.glob(".named-lane-launch-*")), ())
        finally:
            if parent.exists():
                parent.rmdir()
            if displaced.exists():
                displaced.rmdir()

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "prelaunch session cleanup requires POSIX pthread_sigmask",
    )
    def test_prelaunch_session_cleanup_precedes_signal_restore_failures(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        executable = self.make_executable("pass\n", version="2.1.226")
        session_parent = home / ".claude" / "session-env"
        initial_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        real_restore = named_lane_runtime.restore_signal_mask

        for label in ("mask-restore", "deferred-signal"):
            with self.subTest(label=label):
                leaf = session_parent / (
                    "00000000-0000-4000-8000-"
                    f"{1 if label == 'mask-restore' else 2:012d}"
                )
                prepare_error: (
                    named_lane_runtime._ClaudeSessionEnvCleanupError | None
                ) = None
                prepare_cause = OSError("synthetic prelaunch validation failure")
                mask_restore_error = NamedLaneGuardError(
                    "synthetic signal mask restoration failure"
                )

                def fail_after_leaf_creation(
                    candidate_home: pathlib.Path,
                ) -> object:
                    nonlocal prepare_error
                    self.assertEqual(candidate_home, home)
                    leaf.mkdir(mode=0o700)
                    leaf.chmod(0o700)
                    parent_metadata = session_parent.stat()
                    leaf_metadata = leaf.stat()
                    prepare_error = named_lane_runtime._ClaudeSessionEnvCleanupError(
                        None,
                        "prelaunch",
                        retained_parent_identity=(
                            parent_metadata.st_dev,
                            parent_metadata.st_ino,
                        ),
                        retained_leaf=leaf.name,
                        retained_leaf_identity=(
                            leaf_metadata.st_dev,
                            leaf_metadata.st_ino,
                        ),
                    )
                    if label == "mask-restore":
                        try:
                            raise prepare_cause
                        except OSError:
                            raise prepare_error
                    raise prepare_error from prepare_cause

                def restore_with_secondary(
                    previous_mask: set[signal.Signals],
                ) -> signal.Signals | None:
                    real_restore(previous_mask)
                    if label == "deferred-signal":
                        return signal.SIGTERM
                    raise mask_restore_error

                try:
                    with (
                        mock.patch(
                            "pwd.getpwuid",
                            return_value=self.claude_account(home),
                        ),
                        mock.patch.object(
                            named_lane_runtime,
                            "_prepare_claude_session_env",
                            side_effect=fail_after_leaf_creation,
                        ),
                        mock.patch.object(
                            named_lane_runtime,
                            "_restore_claude_snapshot_signal_mask",
                            side_effect=restore_with_secondary,
                        ),
                        self.assertRaises(
                            named_lane_runtime._ClaudeSessionEnvCleanupError
                        ) as context,
                    ):
                        self.run_claude(
                            worktree=self.repo.resolve(),
                            stdout_path=self.root / f"prelaunch-{label}.out",
                            stderr_path=self.root / f"prelaunch-{label}.err",
                            command=(str(executable),),
                            prompt=b"",
                            timeout_seconds=2.0,
                            stream_limit_bytes=16 * 1024,
                        )

                    error = context.exception
                    self.assertIs(error, prepare_error)
                    self.assertEqual(error.process_reason, "prelaunch")
                    self.assertIsNone(error.retained_path)
                    parent_metadata = session_parent.stat()
                    leaf_metadata = leaf.stat()
                    self.assertEqual(
                        error.retained_parent_identity,
                        (parent_metadata.st_dev, parent_metadata.st_ino),
                    )
                    self.assertEqual(error.retained_leaf, leaf.name)
                    self.assertEqual(
                        error.retained_leaf_identity,
                        (leaf_metadata.st_dev, leaf_metadata.st_ino),
                    )
                    self.assertTrue(leaf.is_dir())
                    if label == "mask-restore":
                        self.assertIs(error.__cause__, mask_restore_error)
                    else:
                        self.assertIsInstance(error.__cause__, ForwardedSignal)
                        self.assertEqual(error.__cause__.signum, signal.SIGTERM)
                    self.assertIs(error.__cause__.__context__, prepare_cause)
                    self.assertIsNot(error.__cause__.__context__, error)
                    self.assertEqual(
                        signal.pthread_sigmask(signal.SIG_BLOCK, set()),
                        initial_mask,
                    )
                    self.assertEqual(tuple(self.root.glob(".named-lane-launch-*")), ())
                    self.assertFalse((self.root / f"prelaunch-{label}.out").exists())
                    self.assertFalse((self.root / f"prelaunch-{label}.err").exists())
                finally:
                    real_restore(initial_mask)
                    if leaf.exists():
                        leaf.rmdir()

    @unittest.skipUnless(os.name == "posix", "session environment requires POSIX")
    def test_claude_session_env_is_retained_without_quiescence_proof(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        executable = self.make_executable("pass\n", version="2.1.226")
        real_capture = named_lane_runtime.run_bounded_capture

        for label, process_error, process_reason in (
            ("process-leak", ReviewProcessLeakError("synthetic leak"), "process-leak"),
            (
                "output-drain",
                ReviewOutputDrainError("synthetic drain failure"),
                "output-drain",
            ),
        ):
            with self.subTest(label=label):

                def fail_without_quiescence(
                    argv: object,
                    **kwargs: object,
                ) -> object:
                    if str(tuple(argv)[0]).startswith(
                        str(self.root / ".named-lane-launch-")
                    ):
                        self.assertTrue(callable(kwargs["on_process_quiescent"]))
                        raise process_error
                    return real_capture(argv, **kwargs)

                retained: pathlib.Path | None = None
                try:
                    with (
                        mock.patch(
                            "pwd.getpwuid",
                            return_value=self.claude_account(home),
                        ),
                        mock.patch.object(
                            named_lane_runtime,
                            "run_bounded_capture",
                            side_effect=fail_without_quiescence,
                        ),
                        self.assertRaises(
                            named_lane_runtime._ClaudeSessionEnvCleanupError
                        ) as context,
                    ):
                        self.run_claude(
                            worktree=self.repo.resolve(),
                            stdout_path=self.root / f"unquiescent-{label}.out",
                            stderr_path=self.root / f"unquiescent-{label}.err",
                            command=(str(executable),),
                            prompt=b"",
                            timeout_seconds=2.0,
                            stream_limit_bytes=16 * 1024,
                        )

                    error = context.exception
                    retained = error.retained_path
                    self.assertEqual(error.process_reason, process_reason)
                    self.assertTrue(error.retained_for_quiescence)
                    self.assertIsNotNone(retained)
                    assert retained is not None
                    parent_metadata = retained.parent.stat()
                    leaf_metadata = retained.stat()
                    self.assertEqual(
                        error.retained_parent_identity,
                        (parent_metadata.st_dev, parent_metadata.st_ino),
                    )
                    self.assertEqual(error.retained_leaf, retained.name)
                    self.assertEqual(
                        error.retained_leaf_identity,
                        (leaf_metadata.st_dev, leaf_metadata.st_ino),
                    )
                    self.assertEqual(list(retained.iterdir()), [])
                    self.assertFalse((self.root / f"unquiescent-{label}.out").exists())
                    self.assertFalse((self.root / f"unquiescent-{label}.err").exists())
                finally:
                    if retained is not None:
                        retained.rmdir()

    @unittest.skipUnless(os.name == "posix", "session environment requires POSIX")
    def test_session_env_is_retained_when_capture_returns_without_proof(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        executable = self.make_executable("pass\n", version="2.1.226")
        real_capture = named_lane_runtime.run_bounded_capture
        retained: pathlib.Path | None = None

        def complete_without_quiescence(
            argv: object,
            **kwargs: object,
        ) -> object:
            nonlocal retained
            arguments = tuple(str(argument) for argument in argv)
            if not arguments[0].startswith(str(self.root / ".named-lane-launch-")):
                return real_capture(argv, **kwargs)
            session_index = arguments.index("--session-id")
            retained = home / ".claude" / "session-env" / arguments[session_index + 1]
            self.assertTrue(callable(kwargs["on_process_quiescent"]))
            return BoundedCapture(arguments, 0, bytearray(), bytearray())

        try:
            with (
                mock.patch(
                    "pwd.getpwuid",
                    return_value=self.claude_account(home),
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "run_bounded_capture",
                    side_effect=complete_without_quiescence,
                ),
                self.assertRaises(
                    named_lane_runtime._ClaudeSessionEnvCleanupError
                ) as context,
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=self.root / "capture-without-proof.out",
                    stderr_path=self.root / "capture-without-proof.err",
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=16 * 1024,
                )

            error = context.exception
            self.assertEqual(error.process_reason, "process-leak")
            self.assertTrue(error.retained_for_quiescence)
            self.assertEqual(error.retained_path, retained)
            self.assertIsInstance(error.__cause__, ReviewProcessLeakError)
            assert retained is not None
            self.assertTrue(retained.is_dir())
            self.assertEqual(list(retained.iterdir()), [])
            self.assertFalse((self.root / "capture-without-proof.out").exists())
            self.assertFalse((self.root / "capture-without-proof.err").exists())
        finally:
            if retained is not None:
                retained.rmdir()

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "session cleanup mask requires POSIX pthread_sigmask",
    )
    def test_unquiescent_session_env_survives_cleanup_mask_acquisition_failure(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        executable = self.make_executable("pass\n", version="2.1.226")
        real_block = named_lane_runtime.block_forwarded_signals
        real_capture = named_lane_runtime.run_bounded_capture
        real_restore = named_lane_runtime.restore_signal_mask
        initial_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        block_calls = 0
        capture_entered = False
        process_error = ReviewProcessLeakError("synthetic process leak")
        retained_leaf: pathlib.Path | None = None
        retained_snapshot: pathlib.Path | None = None

        def fail_cleanup_mask() -> set[signal.Signals] | None:
            nonlocal block_calls
            block_calls += 1
            if block_calls == 2:
                return None
            return real_block()

        def fail_without_quiescence(
            _argv: object,
            **kwargs: object,
        ) -> object:
            nonlocal capture_entered, retained_leaf, retained_snapshot
            arguments = tuple(_argv)
            if not str(arguments[0]).startswith(str(self.root / ".named-lane-launch-")):
                return real_capture(_argv, **kwargs)
            capture_entered = True
            retained_snapshot = pathlib.Path(str(arguments[0]))
            session_index = arguments.index("--session-id")
            retained_leaf = (
                home / ".claude" / "session-env" / str(arguments[session_index + 1])
            )
            self.assertTrue(callable(kwargs["on_process_quiescent"]))
            raise process_error

        try:
            with (
                mock.patch(
                    "pwd.getpwuid",
                    return_value=self.claude_account(home),
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "block_forwarded_signals",
                    side_effect=fail_cleanup_mask,
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "run_bounded_capture",
                    side_effect=fail_without_quiescence,
                ),
                self.assertRaises(
                    named_lane_runtime._ClaudeControlCleanupError
                ) as context,
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=self.root / "unquiescent-mask-acquire.out",
                    stderr_path=self.root / "unquiescent-mask-acquire.err",
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=16 * 1024,
                )

            session_error = context.exception.session_env
            self.assertTrue(capture_entered)
            self.assertEqual(block_calls, 2)
            self.assertEqual(session_error.process_reason, "process-leak")
            self.assertTrue(session_error.retained_for_quiescence)
            self.assertIs(session_error.__cause__, process_error)
            self.assertEqual(session_error.retained_path, retained_leaf)
            self.assertEqual(
                context.exception.snapshot.retained_path, retained_snapshot
            )
            assert retained_leaf is not None
            self.assertTrue(retained_leaf.is_dir())
            self.assertEqual(list(retained_leaf.iterdir()), [])
            self.assertFalse((self.root / "unquiescent-mask-acquire.out").exists())
            self.assertFalse((self.root / "unquiescent-mask-acquire.err").exists())
        finally:
            real_restore(initial_mask)
            if retained_leaf is not None:
                retained_leaf.rmdir()
            if retained_snapshot is not None:
                retained_snapshot.unlink()

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "session cleanup mask requires POSIX pthread_sigmask",
    )
    def test_quiescent_session_env_survives_cleanup_mask_acquisition_failure(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        executable = self.make_executable("pass\n", version="2.1.226")
        real_block = named_lane_runtime.block_forwarded_signals
        real_restore = named_lane_runtime.restore_signal_mask
        initial_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        block_calls = 0
        retained_leaf: pathlib.Path | None = None
        retained_snapshot: pathlib.Path | None = None

        def fail_cleanup_mask() -> set[signal.Signals] | None:
            nonlocal block_calls
            block_calls += 1
            if block_calls == 2:
                return None
            return real_block()

        try:
            with (
                mock.patch(
                    "pwd.getpwuid",
                    return_value=self.claude_account(home),
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "block_forwarded_signals",
                    side_effect=fail_cleanup_mask,
                ),
                self.assertRaises(
                    named_lane_runtime._ClaudeControlCleanupError
                ) as context,
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=self.root / "quiescent-mask-acquire.out",
                    stderr_path=self.root / "quiescent-mask-acquire.err",
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=16 * 1024,
                )

            session_error = context.exception.session_env
            self.assertEqual(block_calls, 2)
            self.assertEqual(session_error.process_reason, "signal-mask-unavailable")
            self.assertFalse(session_error.retained_for_quiescence)
            retained_leaf = session_error.retained_path
            retained_snapshot = context.exception.snapshot.retained_path
            self.assertIsNotNone(retained_leaf)
            self.assertIsNotNone(retained_snapshot)
            assert retained_leaf is not None
            assert retained_snapshot is not None
            self.assertTrue(retained_leaf.is_dir())
            self.assertTrue(retained_snapshot.is_file())
            self.assertFalse((self.root / "quiescent-mask-acquire.out").exists())
            self.assertFalse((self.root / "quiescent-mask-acquire.err").exists())
        finally:
            real_restore(initial_mask)
            if retained_leaf is not None:
                retained_leaf.rmdir()
            if retained_snapshot is not None:
                retained_snapshot.unlink()

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "session cleanup mask requires POSIX pthread_sigmask",
    )
    def test_unquiescent_session_env_preserves_output_drain_after_mask_restore_failure(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        executable = self.make_executable("pass\n", version="2.1.226")
        real_capture = named_lane_runtime.run_bounded_capture
        real_restore = named_lane_runtime.restore_signal_mask
        initial_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        restore_calls = 0
        capture_entered = False
        process_error = ReviewOutputDrainError("synthetic output drain failure")
        retained_leaf: pathlib.Path | None = None

        def fail_cleanup_mask_restores(previous: object) -> None:
            nonlocal restore_calls
            restore_calls += 1
            if restore_calls == 1:
                real_restore(previous)
                return
            raise OSError("synthetic cleanup mask restore failure")

        def fail_without_quiescence(
            _argv: object,
            **kwargs: object,
        ) -> object:
            nonlocal capture_entered, retained_leaf
            arguments = tuple(_argv)
            if not str(arguments[0]).startswith(str(self.root / ".named-lane-launch-")):
                return real_capture(_argv, **kwargs)
            capture_entered = True
            session_index = arguments.index("--session-id")
            retained_leaf = (
                home / ".claude" / "session-env" / str(arguments[session_index + 1])
            )
            self.assertTrue(callable(kwargs["on_process_quiescent"]))
            raise process_error

        try:
            with (
                mock.patch(
                    "pwd.getpwuid",
                    return_value=self.claude_account(home),
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "restore_signal_mask",
                    side_effect=fail_cleanup_mask_restores,
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "run_bounded_capture",
                    side_effect=fail_without_quiescence,
                ),
                self.assertRaises(
                    named_lane_runtime._ClaudeSessionEnvCleanupError
                ) as context,
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=self.root / "unquiescent-mask-restore.out",
                    stderr_path=self.root / "unquiescent-mask-restore.err",
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=16 * 1024,
                )

            error = context.exception
            self.assertTrue(capture_entered)
            self.assertEqual(restore_calls, 3)
            self.assertEqual(error.process_reason, "output-drain")
            self.assertTrue(error.retained_for_quiescence)
            self.assertEqual(error.retained_path, retained_leaf)
            assert retained_leaf is not None
            self.assertTrue(retained_leaf.is_dir())
            self.assertEqual(list(retained_leaf.iterdir()), [])
            self.assertFalse((self.root / "unquiescent-mask-restore.out").exists())
            self.assertFalse((self.root / "unquiescent-mask-restore.err").exists())
        finally:
            real_restore(initial_mask)
            if retained_leaf is not None:
                retained_leaf.rmdir()

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "deferred signal cleanup requires POSIX pthread_sigmask",
    )
    def test_unquiescent_session_env_preserves_output_drain_after_deferred_signal(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        executable = self.make_executable("pass\n", version="2.1.226")
        real_capture = named_lane_runtime.run_bounded_capture
        process_error = ReviewOutputDrainError("synthetic output drain failure")
        retained_leaf: pathlib.Path | None = None
        initial_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        real_restore = named_lane_runtime.restore_signal_mask

        def fail_without_quiescence(
            argv: object,
            **kwargs: object,
        ) -> object:
            nonlocal retained_leaf
            arguments = tuple(argv)
            if not str(arguments[0]).startswith(str(self.root / ".named-lane-launch-")):
                return real_capture(argv, **kwargs)
            session_index = arguments.index("--session-id")
            retained_leaf = (
                home / ".claude" / "session-env" / str(arguments[session_index + 1])
            )
            self.assertTrue(callable(kwargs["on_process_quiescent"]))
            raise process_error

        def restore_with_deferred_signal(
            previous_mask: set[signal.Signals],
        ) -> signal.Signals:
            real_restore(previous_mask)
            return signal.SIGTERM

        try:
            with (
                mock.patch(
                    "pwd.getpwuid",
                    return_value=self.claude_account(home),
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "run_bounded_capture",
                    side_effect=fail_without_quiescence,
                ),
                mock.patch.object(
                    named_lane_runtime,
                    "_restore_claude_snapshot_signal_mask",
                    side_effect=restore_with_deferred_signal,
                ),
                self.assertRaises(
                    named_lane_runtime._ClaudeSessionEnvCleanupError
                ) as context,
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=self.root / "unquiescent-deferred-signal.out",
                    stderr_path=self.root / "unquiescent-deferred-signal.err",
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=16 * 1024,
                )

            error = context.exception
            self.assertEqual(error.process_reason, "output-drain")
            self.assertTrue(error.retained_for_quiescence)
            self.assertEqual(error.retained_path, retained_leaf)
            self.assertIsInstance(error.__cause__, ForwardedSignal)
            self.assertEqual(error.__cause__.signum, signal.SIGTERM)
            assert retained_leaf is not None
            self.assertTrue(retained_leaf.is_dir())
            self.assertEqual(
                signal.pthread_sigmask(signal.SIG_BLOCK, set()),
                initial_mask,
            )
            self.assertFalse((self.root / "unquiescent-deferred-signal.out").exists())
            self.assertFalse((self.root / "unquiescent-deferred-signal.err").exists())
        finally:
            real_restore(initial_mask)
            if retained_leaf is not None:
                retained_leaf.rmdir()

    @unittest.skipUnless(os.name == "posix", "session environment requires POSIX")
    def test_claude_session_env_is_removed_after_proven_quiescence(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        executable = self.make_executable("pass\n", version="2.1.226")
        real_capture = named_lane_runtime.run_bounded_capture

        for label, process_error in (
            ("deadline", ReviewTimeoutError("synthetic deadline")),
            ("output-limit", ReviewOutputLimitError("synthetic output limit")),
            ("process-leak", ReviewProcessLeakError("conservative synthetic leak")),
        ):
            with self.subTest(label=label):

                def fail_after_quiescence(
                    argv: object,
                    **kwargs: object,
                ) -> object:
                    if str(tuple(argv)[0]).startswith(
                        str(self.root / ".named-lane-launch-")
                    ):
                        callback = kwargs["on_process_quiescent"]
                        assert callable(callback)
                        callback()
                        raise process_error
                    return real_capture(argv, **kwargs)

                with (
                    mock.patch(
                        "pwd.getpwuid",
                        return_value=self.claude_account(home),
                    ),
                    mock.patch.object(
                        named_lane_runtime,
                        "run_bounded_capture",
                        side_effect=fail_after_quiescence,
                    ),
                    self.assertRaises(type(process_error)) as context,
                ):
                    self.run_claude(
                        worktree=self.repo.resolve(),
                        stdout_path=self.root / f"quiescent-{label}.out",
                        stderr_path=self.root / f"quiescent-{label}.err",
                        command=(str(executable),),
                        prompt=b"",
                        timeout_seconds=2.0,
                        stream_limit_bytes=16 * 1024,
                    )

                self.assertIs(context.exception, process_error)
                self.assertEqual(
                    list((home / ".claude" / "session-env").iterdir()),
                    [],
                )

    @unittest.skipUnless(os.name == "posix", "session environment requires POSIX")
    def test_claude_2_1_225_receives_the_exact_guard_owned_profile(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        source_base, source_head = self.source_control_range()
        source_receipt = self.prepare_source_authority_receipt(
            self.source_control,
            base=source_base,
            head=source_head,
            name="exact-profile-source",
        )
        source_binding = source_receipt["source_authority_binding"]
        source_binding_sha256 = source_receipt["source_authority_binding_sha256"]
        self.assertIsInstance(source_binding, dict)
        self.assertIsInstance(source_binding_sha256, str)
        home = self.make_claude_home()
        executable = self.make_executable(
            "import json, os, sys\n"
            "json.dump({'arguments': sys.argv[1:], "
            "'environment': dict(os.environ)}, sys.stdout)\n",
            version="2.1.225",
        )
        stdout = self.root / "pre-session-env.json"
        stderr = self.root / "pre-session-env.err"
        with mock.patch("pwd.getpwuid", return_value=self.claude_account(home)):
            requested_environment = named_lane_runtime._claude_environment(
                self.repo.resolve()
            )
            result = self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=stdout,
                stderr_path=stderr,
                command=(str(executable),),
                source_authority_binding=source_binding,
                source_authority_binding_sha256=source_binding_sha256,
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )

        observed = json.loads(stdout.read_text(encoding="utf-8"))
        self.assertEqual(result["status"], "complete")
        self.assertNotIn("--session-id", observed["arguments"])
        self.assertNotIn("session_id", result["launch_binding"])
        self.assertNotIn("session_env", result["launch_binding"])
        self.assertEqual(list((home / ".claude" / "session-env").iterdir()), [])

        profile = result["launch_binding"]["argv_profile"]
        settings = profile["settings"]
        settings_json = json.dumps(
            settings,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        expected_arguments = [
            "--print",
            "--input-format",
            "text",
            "--model",
            "claude-opus-4-8",
            "--effort",
            "max",
            "--permission-mode",
            "dontAsk",
            "--output-format",
            "stream-json",
            "--verbose",
            "--no-session-persistence",
            "--safe-mode",
            "--no-chrome",
            "--disable-slash-commands",
            "--strict-mcp-config",
            "--mcp-config",
            '{"mcpServers":{}}',
            "--setting-sources",
            "",
            "--settings",
            settings_json,
            "--tools",
            "Read,Grep,Glob,Bash",
            "--allowedTools",
            "Read(./**),Grep,Glob,Bash",
            "--disallowedTools",
            "Edit,Write,NotebookEdit,WebFetch,WebSearch",
        ]
        self.assertEqual(observed["arguments"], expected_arguments)
        self.assertEqual(profile["guard_constructed_arguments"], expected_arguments)
        self.assertEqual(profile["effective_arguments"], expected_arguments)
        self.assertEqual(profile["profile"], "named-direct-claude-argv-v3")
        self.assertEqual(
            profile["conformance"], "guard-constructed-exact-token-sequence"
        )
        self.assertEqual(profile["settings_schema"], "named-direct-claude-settings-v1")
        self.assertEqual(profile["settings_assurance"], "requested-configuration-only")
        self.assertIs(profile["settings_parser_acceptance_attested"], False)
        self.assertIs(profile["managed_policy_residual"], True)
        self.assertIs(profile["native_sandbox_effectiveness_attested"], False)
        self.assertEqual(profile["model"], "claude-opus-4-8")
        self.assertEqual(profile["effort"], "max")
        self.assertEqual(profile["worktree"], str(self.repo.resolve()))
        self.assertEqual(
            profile["review_git_metadata"], str((self.repo / ".git").resolve())
        )
        self.assertEqual(profile["account_home"], str(home))
        self.assertEqual(profile["source_worktree"], str(self.source_control))
        self.assertEqual(
            profile["source_worktree_binding"],
            "prepare-workspace-receipt-exact-digest-bound-authority-v1",
        )
        self.assertEqual(profile["source_authority_binding"], source_binding)
        self.assertEqual(
            profile["source_authority_binding_sha256"],
            source_binding_sha256,
        )
        self.assertNotIn("--source-authority-binding-json", observed["arguments"])
        self.assertNotIn("--source-authority-binding-sha256", observed["arguments"])
        self.assertEqual(
            profile["source_read_deny_roots"],
            [str(self.source_control), str(self.source_control / ".git")],
        )
        self.assertEqual(profile["source_authority_policy"], "direct-primary-only")
        self.assertEqual(
            profile["source_primary_object_store"],
            str(self.source_control / ".git/objects"),
        )
        self.assertEqual(
            profile["source_primary_object_store_identity"]["uid"],
            os.getuid(),
        )
        self.assertEqual(
            profile["source_authority_revalidation"],
            ["pre-spawn", "pre-terminal-acceptance"],
        )
        self.assertEqual(
            profile["preflight_result"], str(self.preflight_result_path(executable))
        )
        self.assertEqual(set(profile["output_bindings"]), {"stdout", "stderr"})
        for label, path in (("stdout", stdout), ("stderr", stderr)):
            binding = profile["output_bindings"][label]
            self.assertEqual(binding["path"], str(path))
            self.assertEqual(binding["parent"], str(path.parent))
            self.assertEqual(binding["parent_identity"]["uid"], os.getuid())
            self.assertEqual(binding["parent_identity"]["mode"], 0o700)

        self.assertEqual(
            set(settings),
            {
                "disableAllHooks",
                "disableBundledSkills",
                "permissions",
                "sandbox",
            },
        )
        self.assertIs(settings["disableAllHooks"], True)
        self.assertIs(settings["disableBundledSkills"], True)
        self.assertEqual(
            settings["permissions"],
            {
                "deny": [
                    "Edit",
                    "Write",
                    "NotebookEdit",
                    "WebFetch",
                    "WebSearch",
                ]
            },
        )
        sandbox = settings["sandbox"]
        self.assertEqual(
            set(sandbox),
            {
                "allowUnsandboxedCommands",
                "autoAllowBashIfSandboxed",
                "credentials",
                "enabled",
                "enableWeakerNestedSandbox",
                "enableWeakerNetworkIsolation",
                "excludedCommands",
                "failIfUnavailable",
                "filesystem",
                "network",
            },
        )
        self.assertIs(sandbox["allowUnsandboxedCommands"], False)
        self.assertIs(sandbox["autoAllowBashIfSandboxed"], False)
        self.assertIs(sandbox["enabled"], True)
        self.assertIs(sandbox["enableWeakerNestedSandbox"], False)
        self.assertIs(sandbox["enableWeakerNetworkIsolation"], False)
        self.assertEqual(sandbox["excludedCommands"], [])
        self.assertIs(sandbox["failIfUnavailable"], True)
        self.assertEqual(
            sandbox["network"],
            {
                "allowAllUnixSockets": False,
                "allowLocalBinding": False,
                "allowUnixSockets": [],
                "allowedDomains": [],
            },
        )
        filesystem = sandbox["filesystem"]
        self.assertEqual(
            filesystem["allowRead"],
            [
                str(self.repo.resolve()),
                str((self.repo / ".git").resolve()),
                "/dev/null",
            ],
        )
        self.assertEqual(filesystem["denyWrite"], ["/"])
        self.assertNotIn("allowWrite", filesystem)
        self.assertEqual(
            set(filesystem["denyRead"]),
            {
                *(
                    str(home / path)
                    for path in (
                        ".aws",
                        ".claude",
                        ".codex",
                        ".config",
                        ".copilot",
                        ".gnupg",
                        ".kube",
                        ".ssh",
                        ".git-credentials",
                        ".netrc",
                    )
                ),
                str(self.source_control),
                str(self.source_control / ".git"),
                str(self.preflight_result_path(executable)),
                str(stdout),
                str(stderr),
                "/proc",
                "/dev",
            },
        )
        self.assertEqual(
            sandbox["credentials"]["files"],
            [
                {"mode": "deny", "path": str(home / path)}
                for path in (
                    ".aws",
                    ".claude",
                    ".codex",
                    ".config",
                    ".copilot",
                    ".gnupg",
                    ".kube",
                    ".ssh",
                    ".git-credentials",
                    ".netrc",
                )
            ],
        )
        self.assertEqual(
            sandbox["credentials"]["envVars"],
            [
                {"mode": "deny", "name": name}
                for name in named_lane_runtime.CLAUDE_DIRECT_SECRET_ENVIRONMENT_KEYS
            ],
        )

        git_null_binding = profile["git_null_read_exception"]
        self.assertEqual(
            set(git_null_binding), {"path", "identity_binding", "identity"}
        )
        self.assertEqual(git_null_binding["path"], filesystem["allowRead"][-1])
        self.assertEqual(
            git_null_binding["identity_binding"],
            "canonical-no-follow-character-device",
        )
        null_metadata = pathlib.Path("/dev/null").lstat()
        self.assertEqual(
            git_null_binding["identity"],
            {
                "device": null_metadata.st_dev,
                "inode": null_metadata.st_ino,
                "file_type": stat.S_IFMT(null_metadata.st_mode),
                "mode": stat.S_IMODE(null_metadata.st_mode),
                "uid": null_metadata.st_uid,
                "gid": null_metadata.st_gid,
                "rdev": null_metadata.st_rdev,
            },
        )

        canonical = named_lane_runtime._canonical_json_bytes
        self.assertEqual(
            profile["settings_sha256"],
            hashlib.sha256(settings_json.encode()).hexdigest(),
        )
        self.assertEqual(
            profile["guard_constructed_arguments_sha256"],
            hashlib.sha256(canonical(expected_arguments)).hexdigest(),
        )
        self.assertEqual(
            profile["effective_arguments_sha256"],
            hashlib.sha256(canonical(expected_arguments)).hexdigest(),
        )
        profile_without_digest = dict(profile)
        observed_profile_digest = profile_without_digest.pop("profile_sha256")
        self.assertEqual(
            observed_profile_digest,
            hashlib.sha256(canonical(profile_without_digest)).hexdigest(),
        )
        environment_binding = profile["environment_binding"]
        self.assertEqual(
            environment_binding["profile"], "named-direct-claude-environment-v1"
        )
        self.assertEqual(
            environment_binding["assurance"],
            "guard-supplied-process-environment",
        )
        self.assertEqual(
            environment_binding["requested_keys"], sorted(requested_environment)
        )
        self.assertEqual(
            environment_binding["requested_environment_sha256"],
            hashlib.sha256(canonical(requested_environment)).hexdigest(),
        )
        self.assertEqual(
            {
                key: value
                for key, value in observed["environment"].items()
                if key != "__CF_USER_TEXT_ENCODING"
            },
            requested_environment,
        )
        self.assertIs(environment_binding["node_extra_ca_certs_inherited"], False)
        self.assertNotIn("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB", requested_environment)
        self.assertNotIn(
            "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB",
            environment_binding["requested_keys"],
        )
        permission_index = expected_arguments.index("--permission-mode")
        self.assertEqual(expected_arguments[permission_index + 1], "dontAsk")

    def test_claude_guard_owned_profile_is_primary_model_only(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        for model in ("claude-opus-4-7", "claude-opus-4-8-latest"):
            with self.subTest(model=model):
                marker = self.root / f"invalid-model-{model}.marker"
                invalid = self.make_executable(
                    f"import pathlib\npathlib.Path({str(marker)!r}).touch()\n"
                )
                with self.assertRaisesRegex(
                    NamedLaneGuardError,
                    "model must match the canonical named-direct model profile",
                ):
                    self.run_claude(
                        worktree=self.repo.resolve(),
                        stdout_path=self.root / f"invalid-model-{model}.stdout",
                        stderr_path=self.root / f"invalid-model-{model}.stderr",
                        command=(str(invalid),),
                        model=model,
                        prompt=b"",
                        timeout_seconds=2.0,
                        stream_limit_bytes=16 * 1024,
                    )
                self.assertFalse(marker.exists())

    def test_claude_preflight_options_match_the_guard_owned_argv(self) -> None:
        from review_runtime.claude_capabilities import (
            CLAUDE_NAMED_DIRECT_REQUIRED_OPTIONS,
            named_direct_required_options,
        )

        self.assertEqual(
            named_lane_runtime.CLAUDE_DIRECT_REQUIRED_OPTIONS,
            CLAUDE_NAMED_DIRECT_REQUIRED_OPTIONS,
        )
        for version in ("2.1.211", "2.1.225", "2.1.226", "2.9.999"):
            with self.subTest(version=version):
                parsed = named_lane_runtime.parse_compatible_release_version(version)
                self.assertEqual(
                    named_lane_runtime._claude_direct_required_options(parsed),
                    named_direct_required_options(version),
                )

    def test_claude_rejects_preflight_option_contract_drift(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        cases = (
            ("missing", lambda value: value["required_options"].pop()),
            (
                "duplicate",
                lambda value: value["required_options"].append("--print"),
            ),
            (
                "unknown",
                lambda value: value["required_options"].append("--unsafe-fixture"),
            ),
            ("unaccepted", lambda value: value.__setitem__("status", "unaccepted")),
            ("extra-field", lambda value: value.__setitem__("extra", True)),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                marker = self.root / f"preflight-{label}.marker"
                executable = self.make_executable(
                    f"import pathlib\npathlib.Path({str(marker)!r}).touch()\n"
                )
                preflight = self.preflight_result_path(executable)
                evidence = json.loads(preflight.read_text(encoding="utf-8"))
                mutate(evidence["capability_contract"])
                preflight.write_text(
                    json.dumps(evidence, sort_keys=True), encoding="utf-8"
                )
                with self.assertRaisesRegex(
                    NamedLaneGuardError,
                    "capability contract does not match the closed argv profile",
                ):
                    self.run_claude(
                        worktree=self.repo.resolve(),
                        stdout_path=self.root / f"preflight-{label}.stdout",
                        stderr_path=self.root / f"preflight-{label}.stderr",
                        command=(str(executable),),
                        prompt=b"",
                        timeout_seconds=2.0,
                        stream_limit_bytes=16 * 1024,
                    )
                self.assertFalse(marker.exists())

    def test_cli_run_claude_requires_the_parent_source_binding(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        child_marker = self.root / "missing-source-binding-child"
        executable = self.make_executable(
            f"import pathlib\npathlib.Path({str(child_marker)!r}).touch()\n"
        )
        completed = subprocess.run(
            self.isolated_guard_command(
                SCRIPTS / "named_lane_guard",
                "run-claude",
                "--worktree",
                str(self.repo.resolve()),
                "--source-worktree",
                str(self.source_control),
                "--preflight-result",
                str(self.preflight_result_path(executable)),
                "--stdout-path",
                str(self.root / "missing-binding.stdout"),
                "--stderr-path",
                str(self.root / "missing-binding.stderr"),
                "--",
                str(executable),
                include_prepared_source_authority=False,
            ),
            check=False,
            input=b"review",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, b"")
        self.assertIn(b"--source-authority-binding-json", completed.stderr)
        self.assertIn(b"--source-authority-binding-sha256", completed.stderr)
        self.assertFalse(child_marker.exists())
        self.assertFalse((self.root / "missing-binding.stdout").exists())
        self.assertFalse((self.root / "missing-binding.stderr").exists())

    def test_parent_source_binding_parser_rejects_closed_schema_bypasses(
        self,
    ) -> None:
        source_base, source_head = self.source_control_range()
        receipt = self.prepare_source_authority_receipt(
            self.source_control,
            base=source_base,
            head=source_head,
            name="parser-matrix-source",
        )
        binding = receipt["source_authority_binding"]
        digest = receipt["source_authority_binding_sha256"]
        self.assertIsInstance(binding, dict)
        self.assertIsInstance(digest, str)
        canonical = review_workspace_runtime.canonical_source_authority_binding_bytes(
            binding
        ).decode("utf-8")

        extra = json.loads(canonical)
        extra["extra"] = True
        extra_json = review_workspace_runtime.canonical_source_authority_binding_bytes(
            extra
        ).decode("utf-8")
        wrong_type = json.loads(canonical)
        wrong_type["source_worktree"]["identity"]["device"] = True
        wrong_type_json = (
            review_workspace_runtime.canonical_source_authority_binding_bytes(
                wrong_type
            ).decode("utf-8")
        )
        non_utf8_path = json.loads(canonical)
        non_utf8_path["source_worktree"]["path"] = os.fsdecode(b"/tmp/source-\xff")
        non_utf8_json = (
            review_workspace_runtime.canonical_source_authority_binding_bytes(
                non_utf8_path
            ).decode("utf-8")
        )
        noncanonical = json.dumps(binding, indent=2, sort_keys=True)
        duplicate = canonical.replace(
            "{",
            '{"schema_version":"review-source-authority-binding-v1",',
            1,
        )
        cases = (
            ("digest", canonical, "0" * 64, "digest does not match"),
            (
                "extra",
                extra_json,
                hashlib.sha256(extra_json.encode("utf-8")).hexdigest(),
                "closed schema",
            ),
            (
                "type",
                wrong_type_json,
                hashlib.sha256(wrong_type_json.encode("utf-8")).hexdigest(),
                "identity field device is invalid",
            ),
            (
                "non-utf8-path",
                non_utf8_json,
                hashlib.sha256(non_utf8_json.encode("utf-8")).hexdigest(),
                "path must be valid UTF-8",
            ),
            ("noncanonical", noncanonical, digest, "not canonical"),
            ("duplicate", duplicate, digest, "duplicate key"),
        )
        for label, payload, expected_digest, message in cases:
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(NamedLaneGuardError, message),
            ):
                named_lane_runtime._parse_parent_source_authority_binding_json(
                    payload,
                    expected_digest,
                )

    def test_raw_cli_rejects_parent_binding_before_any_runtime_probe(self) -> None:
        source_base, source_head = self.source_control_range()
        receipt = self.prepare_source_authority_receipt(
            self.source_control,
            base=source_base,
            head=source_head,
            name="raw-parser-ordering-source",
        )
        binding = receipt["source_authority_binding"]
        digest = receipt["source_authority_binding_sha256"]
        self.assertIsInstance(binding, dict)
        self.assertIsInstance(digest, str)
        canonical = review_workspace_runtime.canonical_source_authority_binding_bytes(
            binding
        )
        non_utf8 = json.loads(canonical)
        non_utf8["source_worktree"]["path"] = os.fsdecode(b"/tmp/source-\xff")
        non_utf8_bytes = (
            review_workspace_runtime.canonical_source_authority_binding_bytes(non_utf8)
        )
        duplicate = canonical.decode("utf-8").replace(
            "{",
            '{"schema_version":"review-source-authority-binding-v1",',
            1,
        )
        cases = (
            ("digest-mismatch", canonical.decode("utf-8"), "0" * 64),
            (
                "duplicate-key",
                duplicate,
                hashlib.sha256(duplicate.encode("utf-8")).hexdigest(),
            ),
            ("noncanonical", json.dumps(binding, indent=2), digest),
            (
                "non-utf8-path",
                non_utf8_bytes.decode("utf-8"),
                hashlib.sha256(non_utf8_bytes).hexdigest(),
            ),
        )
        for label, payload, expected_digest in cases:
            with self.subTest(label=label):
                stderr = io.StringIO()
                probes = (
                    "_resolve_worktree_root",
                    "_load_claude_executable_binding",
                    "_bind_claude_source_read_boundary",
                    "_create_claude_launch_snapshot",
                    "_read_control_prompt",
                    "run_claude",
                )
                with contextlib.ExitStack() as stack:
                    observed = [
                        stack.enter_context(
                            mock.patch.object(named_lane_runtime, probe)
                        )
                        for probe in probes
                    ]
                    stack.enter_context(contextlib.redirect_stderr(stderr))
                    returncode = _named_lane_main(
                        (
                            "run-claude",
                            "--source-authority-binding-json",
                            payload,
                            "--source-authority-binding-sha256",
                            expected_digest,
                            "--worktree",
                            str(self.repo.resolve()),
                            "--source-worktree",
                            str(self.source_control),
                            "--preflight-result",
                            str(self.root / f"{label}.preflight.json"),
                            "--stdout-path",
                            str(self.root / f"{label}.stdout"),
                            "--stderr-path",
                            str(self.root / f"{label}.stderr"),
                            "--",
                            "/usr/bin/false",
                        )
                    )

                self.assertEqual(returncode, 2)
                self.assertEqual(
                    json.loads(stderr.getvalue())["status"], "inconclusive"
                )
                for probe in observed:
                    probe.assert_not_called()

    def test_claude_tampered_parent_source_binding_fails_before_snapshot(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        source_base, source_head = self.source_control_range()
        receipt = self.prepare_source_authority_receipt(
            self.source_control,
            base=source_base,
            head=source_head,
            name="tampered-source-binding",
        )
        tampered = json.loads(json.dumps(receipt["source_authority_binding"]))
        tampered["source_worktree"]["identity"]["inode"] += 1
        child_marker = self.root / "tampered-source-binding-child"
        executable = self.make_executable(
            f"import pathlib\npathlib.Path({str(child_marker)!r}).touch()\n"
        )

        with (
            mock.patch.object(
                named_lane_runtime,
                "_create_claude_launch_snapshot",
            ) as create_snapshot,
            self.assertRaisesRegex(NamedLaneGuardError, "digest does not match"),
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                source_worktree=self.source_control,
                source_authority_binding=tampered,
                source_authority_binding_sha256=receipt[
                    "source_authority_binding_sha256"
                ],
                stdout_path=self.root / "tampered-binding.stdout",
                stderr_path=self.root / "tampered-binding.stderr",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )

        create_snapshot.assert_not_called()
        self.assertFalse(child_marker.exists())

    def test_claude_parent_binding_blocks_persistent_ordinary_replacement(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        source_base, source_head = self.source_control_range()
        receipt = self.prepare_source_authority_receipt(
            self.source_control,
            base=source_base,
            head=source_head,
            name="ordinary-replacement-source",
        )
        displaced = self.root / "ordinary-source-outside-deny-read"
        self.source_control.rename(displaced)
        self.source_control.mkdir(mode=0o700)
        git(self.source_control, "init", "-b", "master")
        child_marker = self.root / "ordinary-replacement-child"
        executable = self.make_executable(
            f"import pathlib\npathlib.Path({str(child_marker)!r}).touch()\n"
        )

        with (
            mock.patch.object(
                named_lane_runtime,
                "_create_claude_launch_snapshot",
            ) as create_snapshot,
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "does not match the parent-owned prepare-workspace binding",
            ),
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                source_worktree=self.source_control,
                source_authority_binding=receipt["source_authority_binding"],
                source_authority_binding_sha256=receipt[
                    "source_authority_binding_sha256"
                ],
                stdout_path=self.root / "ordinary-replacement.stdout",
                stderr_path=self.root / "ordinary-replacement.stderr",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )

        create_snapshot.assert_not_called()
        self.assertTrue((displaced / ".git").is_dir())
        self.assertFalse(child_marker.exists())

    def test_claude_parent_binding_blocks_persistent_linked_replacement(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        source_base, source_head = self.source_control_range()
        linked = self.root / "linked-authority-source"
        git(
            self.source_control,
            "worktree",
            "add",
            "--detach",
            str(linked),
            source_head,
        )
        receipt = self.prepare_source_authority_receipt(
            linked,
            base=source_base,
            head=source_head,
            name="linked-replacement-source",
        )
        marker_payload = (linked / ".git").read_bytes()
        admin = pathlib.Path(git(linked, "rev-parse", "--absolute-git-dir")).resolve()
        common = pathlib.Path(
            git(linked, "rev-parse", "--path-format=absolute", "--git-common-dir")
        ).resolve()
        admin_identity = admin.stat().st_ino
        common_identity = common.stat().st_ino
        objects_identity = (common / "objects").stat().st_ino
        displaced = self.root / "linked-source-outside-deny-read"
        linked.rename(displaced)
        linked.mkdir(mode=0o700)
        (linked / ".git").write_bytes(marker_payload)
        child_marker = self.root / "linked-replacement-child"
        executable = self.make_executable(
            f"import pathlib\npathlib.Path({str(child_marker)!r}).touch()\n"
        )

        with (
            mock.patch.object(
                named_lane_runtime,
                "_create_claude_launch_snapshot",
            ) as create_snapshot,
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "does not match the parent-owned prepare-workspace binding",
            ),
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                source_worktree=linked,
                source_authority_binding=receipt["source_authority_binding"],
                source_authority_binding_sha256=receipt[
                    "source_authority_binding_sha256"
                ],
                stdout_path=self.root / "linked-replacement.stdout",
                stderr_path=self.root / "linked-replacement.stderr",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )

        create_snapshot.assert_not_called()
        self.assertEqual(admin.stat().st_ino, admin_identity)
        self.assertEqual(common.stat().st_ino, common_identity)
        self.assertEqual((common / "objects").stat().st_ino, objects_identity)
        self.assertTrue((displaced / ".git").is_file())
        self.assertFalse(child_marker.exists())

    def test_claude_parent_binding_blocks_linked_commondir_replacement(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        source_base, source_head = self.source_control_range()
        linked = self.root / "linked-commondir-source"
        git(
            self.source_control,
            "worktree",
            "add",
            "--detach",
            str(linked),
            source_head,
        )
        receipt = self.prepare_source_authority_receipt(
            linked,
            base=source_base,
            head=source_head,
            name="linked-commondir-replacement",
        )
        admin = pathlib.Path(git(linked, "rev-parse", "--absolute-git-dir")).resolve()
        commondir = admin / "commondir"
        original = commondir.lstat()
        replacement = admin / "commondir.replacement"
        replacement.write_bytes(commondir.read_bytes())
        replacement.chmod(stat.S_IMODE(original.st_mode))
        os.replace(replacement, commondir)
        self.assertNotEqual(commondir.stat().st_ino, original.st_ino)
        child_marker = self.root / "linked-commondir-replacement-child"
        executable = self.make_executable(
            f"import pathlib\npathlib.Path({str(child_marker)!r}).touch()\n"
        )

        with (
            mock.patch.object(
                named_lane_runtime,
                "_create_claude_launch_snapshot",
            ) as create_snapshot,
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "does not match the parent-owned prepare-workspace binding",
            ),
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                source_worktree=linked,
                source_authority_binding=receipt["source_authority_binding"],
                source_authority_binding_sha256=receipt[
                    "source_authority_binding_sha256"
                ],
                stdout_path=self.root / "linked-commondir-replacement.stdout",
                stderr_path=self.root / "linked-commondir-replacement.stderr",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )

        create_snapshot.assert_not_called()
        self.assertFalse(child_marker.exists())

    def test_claude_source_deny_roots_include_linked_git_storage(self) -> None:
        git(self.source_control, "config", "user.name", "Named Lane Source Test")
        git(
            self.source_control,
            "config",
            "user.email",
            "named-lane-source@example.invalid",
        )
        (self.source_control / "tracked.txt").write_text("source\n", encoding="utf-8")
        git(self.source_control, "add", "tracked.txt")
        git(self.source_control, "commit", "-m", "source fixture")
        linked = self.root / "linked-source"
        git(self.source_control, "worktree", "add", "--detach", str(linked), "HEAD")

        source, roots = named_lane_runtime._resolve_claude_source_read_deny_roots(
            linked.resolve()
        )

        admin = pathlib.Path(git(linked, "rev-parse", "--absolute-git-dir")).resolve()
        common = pathlib.Path(git(linked, "rev-parse", "--git-common-dir")).resolve()
        self.assertEqual(source, linked.resolve())
        self.assertEqual(roots, (linked.resolve(), admin, common))
        binding = named_lane_runtime._bind_claude_source_read_boundary(linked.resolve())
        self.assertEqual(binding.objects, common / "objects")
        self.assertEqual(binding.objects_identity.owner, os.getuid())

    def test_claude_source_rejects_every_lexical_alternate_entry(self) -> None:
        info = self.source_control / ".git/objects/info"
        info.mkdir(mode=0o700, exist_ok=True)
        regular_target = self.root / "claude-alternate-target"
        regular_target.write_text("target\n", encoding="utf-8")
        cases = (
            ("empty-regular", lambda path: path.write_bytes(b"")),
            (
                "absolute-regular",
                lambda path: path.write_text(
                    str(self.source_control / ".git/objects") + "\n",
                    encoding="utf-8",
                ),
            ),
            (
                "relative-regular",
                lambda path: path.write_text("../../objects\n", encoding="utf-8"),
            ),
            ("symlink", lambda path: path.symlink_to(regular_target)),
            (
                "dangling-symlink",
                lambda path: path.symlink_to(self.root / "missing-claude-alternate"),
            ),
            ("directory", lambda path: path.mkdir(mode=0o700)),
        )
        for control_name in ("alternates", "http-alternates"):
            for variant, create in cases:
                candidate = info / control_name
                try:
                    create(candidate)
                    with (
                        self.subTest(control=control_name, variant=variant),
                        self.assertRaisesRegex(
                            NamedLaneGuardError,
                            "entry must be absent",
                        ),
                    ):
                        named_lane_runtime._resolve_claude_source_read_deny_roots(
                            self.source_control
                        )
                finally:
                    if candidate.is_symlink() or candidate.is_file():
                        candidate.unlink()
                    elif candidate.is_dir():
                        candidate.rmdir()

    def test_claude_source_object_info_indirection_is_rejected(self) -> None:
        info = self.source_control / ".git/objects/info"
        info.mkdir(mode=0o700, exist_ok=True)
        displaced = self.source_control / ".git/objects/info.direct"
        external = self.root / "claude-external-object-info"
        external.mkdir(mode=0o700)
        info.rename(displaced)
        cases = (
            ("regular", lambda: info.write_bytes(b"")),
            ("symlink", lambda: info.symlink_to(external, target_is_directory=True)),
            (
                "dangling-symlink",
                lambda: info.symlink_to(
                    self.root / "missing-claude-object-info",
                    target_is_directory=True,
                ),
            ),
        )
        try:
            for variant, create in cases:
                try:
                    create()
                    with (
                        self.subTest(variant=variant),
                        self.assertRaisesRegex(
                            NamedLaneGuardError,
                            "object-info storage must be a canonical real",
                        ),
                    ):
                        named_lane_runtime._resolve_claude_source_read_deny_roots(
                            self.source_control
                        )
                finally:
                    if info.is_symlink() or info.is_file():
                        info.unlink()
        finally:
            displaced.rename(info)

    def test_claude_source_primary_objects_symlink_is_rejected(self) -> None:
        objects = self.source_control / ".git/objects"
        displaced = self.source_control / ".git/objects.direct"
        external = self.root / "claude-external-objects"
        external.mkdir(mode=0o700)
        objects.rename(displaced)
        objects.symlink_to(external, target_is_directory=True)
        try:
            with self.assertRaisesRegex(
                NamedLaneGuardError,
                "primary Git object directory must be a canonical real directory",
            ):
                named_lane_runtime._resolve_claude_source_read_deny_roots(
                    self.source_control
                )
        finally:
            objects.unlink()
            displaced.rename(objects)

    def test_claude_source_shallow_promisor_metadata_remains_eligible(self) -> None:
        git(self.source_control, "config", "extensions.partialClone", "origin")
        git(self.source_control, "config", "remote.origin.promisor", "true")
        (self.source_control / ".git/shallow").write_text(
            "0" * 40 + "\n",
            encoding="ascii",
        )
        pack = self.source_control / ".git/objects/pack"
        pack.mkdir(mode=0o700, exist_ok=True)
        (pack / "fixture.promisor").write_text("fixture\n", encoding="utf-8")

        source, roots = named_lane_runtime._resolve_claude_source_read_deny_roots(
            self.source_control
        )

        self.assertEqual(source, self.source_control)
        self.assertEqual(
            roots,
            (self.source_control, self.source_control / ".git"),
        )

    def test_claude_source_revalidation_blocks_alternate_before_spawn(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        child_marker = self.root / "alternate-pre-spawn-child"
        executable = self.make_executable(
            f"import pathlib\npathlib.Path({str(child_marker)!r}).touch()\n",
            version="2.1.225",
        )
        alternate = self.source_control / ".git/objects/info/alternates"
        real_snapshot = named_lane_runtime._create_claude_launch_snapshot

        def snapshot_then_inject(*args: object, **kwargs: object) -> object:
            snapshot = real_snapshot(*args, **kwargs)
            alternate.parent.mkdir(mode=0o700, exist_ok=True)
            alternate.write_bytes(b"")
            return snapshot

        stdout = self.root / "alternate-pre-spawn.out"
        stderr = self.root / "alternate-pre-spawn.err"
        try:
            with (
                mock.patch.object(
                    named_lane_runtime,
                    "_create_claude_launch_snapshot",
                    side_effect=snapshot_then_inject,
                ),
                self.assertRaisesRegex(
                    NamedLaneGuardError,
                    "entry must be absent",
                ),
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=stdout,
                    stderr_path=stderr,
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=16 * 1024,
                )
            self.assertFalse(child_marker.exists())
            self.assertFalse(stdout.exists())
            self.assertFalse(stderr.exists())
            self.assertEqual(tuple(self.root.glob(".named-lane-launch-*")), ())
        finally:
            alternate.unlink(missing_ok=True)

    def test_claude_source_revalidation_blocks_alternate_at_terminal(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        alternate = self.source_control / ".git/objects/info/http-alternates"
        executable = self.make_executable(
            "import pathlib\n"
            f"path = pathlib.Path({str(alternate)!r})\n"
            "path.parent.mkdir(mode=0o700, exist_ok=True)\n"
            "path.write_bytes(b'')\n"
            "print('captured but not accepted')\n",
            version="2.1.225",
        )
        stdout = self.root / "alternate-terminal.out"
        stderr = self.root / "alternate-terminal.err"
        try:
            with self.assertRaisesRegex(
                NamedLaneGuardError,
                "entry must be absent",
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=stdout,
                    stderr_path=stderr,
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=16 * 1024,
                )
            self.assertFalse(stdout.exists())
            self.assertFalse(stderr.exists())
        finally:
            alternate.unlink(missing_ok=True)

    def test_claude_source_revalidation_blocks_primary_replacement_at_terminal(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        objects = self.source_control / ".git/objects"
        displaced = self.source_control / ".git/objects.bound-original"
        mode = stat.S_IMODE(objects.lstat().st_mode)
        executable = self.make_executable(
            "import os, pathlib\n"
            f"objects = pathlib.Path({str(objects)!r})\n"
            f"displaced = pathlib.Path({str(displaced)!r})\n"
            "objects.rename(displaced)\n"
            f"objects.mkdir(mode={mode})\n"
            "print('captured but not accepted')\n",
            version="2.1.225",
        )
        stdout = self.root / "objects-terminal.out"
        stderr = self.root / "objects-terminal.err"
        replaced = False
        try:
            with self.assertRaisesRegex(
                NamedLaneGuardError,
                "authority changed after initial binding",
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=stdout,
                    stderr_path=stderr,
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=16 * 1024,
                )
            replaced = displaced.is_dir()
            self.assertFalse(stdout.exists())
            self.assertFalse(stderr.exists())
        finally:
            if displaced.is_dir():
                objects.rmdir()
                displaced.rename(objects)
            self.assertTrue(replaced)

    def test_claude_source_deny_root_rejects_non_git_alias_and_overlap(self) -> None:
        plain = self.root / "plain-source"
        plain.mkdir(mode=0o700)
        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "exact Git worktree root",
        ):
            named_lane_runtime._resolve_claude_source_read_deny_roots(plain)

        alias = self.root / "source-alias"
        alias.symlink_to(self.source_control, target_is_directory=True)
        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "canonical real directory",
        ):
            named_lane_runtime._resolve_claude_source_read_deny_roots(alias)

        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("raise SystemExit(97)\n")
        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "source and review worktrees must be independent",
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                source_worktree=self.repo.resolve(),
                stdout_path=self.root / "overlap-source.stdout",
                stderr_path=self.root / "overlap-source.stderr",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )

    def test_claude_read_boundary_rejects_every_cross_profile_overlap(self) -> None:
        cases = (
            (pathlib.Path("/review"), pathlib.Path("/review")),
            (pathlib.Path("/review/worktree"), pathlib.Path("/review")),
            (pathlib.Path("/review"), pathlib.Path("/review/control")),
        )
        for allowed, denied in cases:
            with (
                self.subTest(allowed=allowed, denied=denied),
                self.assertRaisesRegex(
                    NamedLaneGuardError,
                    "allowRead and denyRead roots must not overlap",
                ),
            ):
                named_lane_runtime._validate_claude_read_boundary_nonoverlap(
                    allow_read=(allowed,),
                    deny_read=(denied,),
                )

        named_lane_runtime._validate_claude_read_boundary_nonoverlap(
            allow_read=(pathlib.Path("/review/worktree"),),
            deny_read=(pathlib.Path("/review-state"), pathlib.Path("/source")),
        )
        named_lane_runtime._validate_claude_read_boundary_nonoverlap(
            allow_read=(pathlib.Path("/dev/null"),),
            deny_read=(pathlib.Path("/dev"),),
        )
        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "allowRead and denyRead roots must not overlap",
        ):
            named_lane_runtime._validate_claude_read_boundary_nonoverlap(
                allow_read=(pathlib.Path("/dev/zero"),),
                deny_read=(pathlib.Path("/dev"),),
            )

    @unittest.skipUnless(
        os.name == "posix" and pathlib.Path("/dev/zero").exists(),
        "Git null exception validation requires POSIX device nodes",
    )
    def test_claude_git_null_read_exception_is_exact_and_identity_bound(
        self,
    ) -> None:
        binding = named_lane_runtime._claude_git_null_read_exception_binding()
        self.assertEqual(binding["path"], "/dev/null")
        self.assertEqual(
            binding["identity_binding"],
            "canonical-no-follow-character-device",
        )

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "must be exact canonical /dev/null",
        ):
            named_lane_runtime._claude_git_null_read_exception_binding(
                pathlib.Path("/dev/zero")
            )

        with (
            mock.patch.object(
                named_lane_runtime.os,
                "fstat",
                return_value=pathlib.Path("/dev/zero").stat(),
            ),
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "changed during validation",
            ),
        ):
            named_lane_runtime._claude_git_null_read_exception_binding()

    @unittest.skipUnless(
        os.name == "posix",
        "Git null exception receipt binding requires POSIX",
    )
    def test_claude_git_null_identity_drift_blocks_receipt_publication(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        executable = self.make_executable("pass\n", version="2.1.225")
        stdout = self.root / "null-drift.stdout"
        stderr = self.root / "null-drift.stderr"
        initial = named_lane_runtime._claude_git_null_read_exception_binding()
        changed = json.loads(json.dumps(initial))
        changed["identity"]["inode"] += 1

        with (
            mock.patch("pwd.getpwuid", return_value=self.claude_account(home)),
            mock.patch.object(
                named_lane_runtime,
                "_claude_git_null_read_exception_binding",
                side_effect=(initial, changed),
            ),
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "changed before receipt generation",
            ),
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=stdout,
                stderr_path=stderr,
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )

        self.assertFalse(stdout.exists())
        self.assertFalse(stderr.exists())

    @unittest.skipUnless(os.name == "posix", "account environment requires POSIX")
    def test_claude_environment_rejects_mismatched_real_and_effective_users(
        self,
    ) -> None:
        with (
            mock.patch.object(named_lane_runtime.os, "getuid", return_value=501),
            mock.patch.object(named_lane_runtime.os, "geteuid", return_value=0),
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "matching real and effective users",
            ),
        ):
            named_lane_runtime._claude_environment(self.repo.resolve())

    @unittest.skipUnless(os.name == "posix", "session environment requires POSIX")
    def test_claude_session_env_parent_is_created_descriptor_relatively(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        (home / ".claude" / "session-env").rmdir()
        executable = self.make_executable(
            "import os, pathlib, sys\n"
            "arguments = sys.argv[1:]\n"
            "session_id = arguments[arguments.index('--session-id') + 1]\n"
            "leaf = pathlib.Path(os.environ['HOME']) / '.claude' / "
            "'session-env' / session_id\n"
            "leaf.mkdir(exist_ok=True)\n",
            version="2.1.226",
        )
        with mock.patch("pwd.getpwuid", return_value=self.claude_account(home)):
            result = self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "session-env-parent.out",
                stderr_path=self.root / "session-env-parent.err",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )

        self.assertEqual(result["status"], "complete")
        parent = home / ".claude" / "session-env"
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o700)
        self.assertEqual(list(parent.iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "session environment requires POSIX")
    def test_claude_session_env_cleanup_preserves_nonempty_leaf(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        executable = self.make_executable(
            "import os, pathlib, sys\n"
            "arguments = sys.argv[1:]\n"
            "session_id = arguments[arguments.index('--session-id') + 1]\n"
            "leaf = pathlib.Path(os.environ['HOME']) / '.claude' / "
            "'session-env' / session_id\n"
            "(leaf / 'unexpected').write_text('retained', encoding='utf-8')\n",
            version="2.1.226",
        )
        with (
            mock.patch("pwd.getpwuid", return_value=self.claude_account(home)),
            self.assertRaises(
                named_lane_runtime._ClaudeSessionEnvCleanupError
            ) as context,
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "session-env-nonempty.out",
                stderr_path=self.root / "session-env-nonempty.err",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )

        retained = context.exception.retained_path
        self.assertEqual(context.exception.process_reason, "complete")
        self.assertIsNotNone(retained)
        assert retained is not None
        self.assertEqual((retained / "unexpected").read_text(), "retained")

    @unittest.skipUnless(os.name == "posix", "session environment requires POSIX")
    def test_claude_session_env_cleanup_preserves_replacement(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        executable = self.make_executable(
            "import os, pathlib, sys\n"
            "arguments = sys.argv[1:]\n"
            "session_id = arguments[arguments.index('--session-id') + 1]\n"
            "parent = pathlib.Path(os.environ['HOME']) / '.claude' / "
            "'session-env'\n"
            "leaf = parent / session_id\n"
            "leaf.rename(parent / f'{session_id}-original')\n"
            "leaf.mkdir(mode=0o700)\n",
            version="2.1.226",
        )
        with (
            mock.patch("pwd.getpwuid", return_value=self.claude_account(home)),
            self.assertRaises(
                named_lane_runtime._ClaudeSessionEnvCleanupError
            ) as context,
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "session-env-replaced.out",
                stderr_path=self.root / "session-env-replaced.err",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )

        locator = context.exception.retained_leaf
        self.assertIsNone(context.exception.retained_path)
        self.assertIsNotNone(locator)
        assert locator is not None
        parent = home / ".claude" / "session-env"
        self.assertTrue((parent / locator).is_dir())
        self.assertTrue((parent / f"{locator}-original").is_dir())

    @unittest.skipUnless(os.name == "posix", "session environment requires POSIX")
    def test_claude_session_env_cleanup_preserves_unsafe_mode_drift(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        executable = self.make_executable(
            "import os, pathlib, sys\n"
            "arguments = sys.argv[1:]\n"
            "session_id = arguments[arguments.index('--session-id') + 1]\n"
            "leaf = pathlib.Path(os.environ['HOME']) / '.claude' / "
            "'session-env' / session_id\n"
            "leaf.chmod(0o750)\n",
            version="2.1.226",
        )
        with (
            mock.patch("pwd.getpwuid", return_value=self.claude_account(home)),
            self.assertRaises(
                named_lane_runtime._ClaudeSessionEnvCleanupError
            ) as context,
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "session-env-mode.out",
                stderr_path=self.root / "session-env-mode.err",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )

        retained = context.exception.retained_path
        self.assertIsNotNone(retained)
        assert retained is not None
        self.assertEqual(stat.S_IMODE(retained.stat().st_mode), 0o750)

    @unittest.skipUnless(os.name == "posix", "session environment requires POSIX")
    def test_claude_session_env_allows_safe_mode_tightening(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        executable = self.make_executable(
            "import os, pathlib, sys\n"
            "arguments = sys.argv[1:]\n"
            "session_id = arguments[arguments.index('--session-id') + 1]\n"
            "parent = pathlib.Path(os.environ['HOME']) / '.claude' / "
            "'session-env'\n"
            "(parent / session_id).chmod(0o600)\n"
            "parent.chmod(0o700)\n",
            version="2.1.226",
        )
        with mock.patch("pwd.getpwuid", return_value=self.claude_account(home)):
            result = self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "session-env-tightening.out",
                stderr_path=self.root / "session-env-tightening.err",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(list((home / ".claude" / "session-env").iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "session environment requires POSIX")
    def test_claude_session_env_parent_drift_is_inconclusive_after_cleanup(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        home = self.make_claude_home()
        displaced = home / ".claude" / "session-env-displaced"
        executable = self.make_executable(
            "import os, pathlib\n"
            "parent = pathlib.Path(os.environ['HOME']) / '.claude' / "
            "'session-env'\n"
            f"parent.rename(pathlib.Path({str(displaced)!r}))\n"
            "parent.mkdir(mode=0o755)\n",
            version="2.1.226",
        )
        with (
            mock.patch("pwd.getpwuid", return_value=self.claude_account(home)),
            self.assertRaises(
                named_lane_runtime._ClaudeSessionEnvCustodyError
            ) as context,
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "session-env-parent-drift.out",
                stderr_path=self.root / "session-env-parent-drift.err",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )

        self.assertEqual(context.exception.cleanup_status, "removed")
        self.assertFalse((displaced / context.exception.session_id).exists())
        self.assertTrue(displaced.is_dir())

    def test_claude_rejects_every_caller_owned_argument(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("raise SystemExit(97)\n", version="2.1.226")
        for selector in (
            ("--print",),
            ("--safe-mode",),
            ("--settings", "{}"),
            ("--settings={}",),
            ("--allowedTools", "Read(./**),Grep,Glob,Bash"),
            ("--unknown",),
            ("--session-id", "00000000-0000-4000-8000-000000000000"),
            ("--session-id=00000000-0000-4000-8000-000000000000",),
            ("--resume", "fixture"),
            ("-rfixture",),
            ("--continue",),
            ("-cfixture",),
            ("--fork-session",),
            ("--fork-session=true",),
            ("--from-pr=123",),
            ("--teleport", "fixture"),
            ("--cloud=fixture",),
            ("--environment", "fixture"),
            ("--remote-control",),
            ("--background",),
            ("--worktree=fixture",),
            ("-wfixture",),
            ("--tmux=classic",),
        ):
            with (
                self.subTest(selector=selector),
                self.assertRaisesRegex(
                    NamedLaneGuardError,
                    "arguments are owned by the named-lane guard",
                ),
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=self.root / f"selector-{selector[0][2:]}.out",
                    stderr_path=self.root / f"selector-{selector[0][2:]}.err",
                    command=(str(executable), *selector),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=16 * 1024,
                )

    @unittest.skipUnless(os.name == "posix", "account environment requires POSIX")
    def test_opted_in_node_extra_ca_rejects_relative_and_symlink_paths(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("pass\n")
        real_ca = self.root / "real-node-ca.pem"
        real_ca.write_text("certificate fixture\n", encoding="ascii")
        linked_ca = self.root / "linked-node-ca.pem"
        linked_ca.symlink_to(real_ca)

        for label, ca_path, message in (
            ("relative", pathlib.Path("node-ca.pem"), "must be absolute"),
            ("symlink", linked_ca, "exact readable regular file"),
        ):
            with self.subTest(label=label):
                with mock.patch.dict(
                    os.environ,
                    {"NODE_EXTRA_CA_CERTS": str(ca_path)},
                    clear=True,
                ):
                    with self.assertRaisesRegex(NamedLaneGuardError, message):
                        self.run_claude(
                            worktree=self.repo.resolve(),
                            stdout_path=self.root / f"{label}.out",
                            stderr_path=self.root / f"{label}.err",
                            command=(str(executable),),
                            prompt=b"",
                            timeout_seconds=1.0,
                            stream_limit_bytes=64,
                            inherit_node_extra_ca_certs=True,
                        )

    @unittest.skipUnless(
        hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
        "requires POSIX FIFO support",
    )
    def test_opted_in_node_extra_ca_fifo_swap_fails_without_blocking(self) -> None:
        node_extra_ca = self.root / "node-extra-ca-swap.pem"
        node_extra_ca.write_text("certificate fixture\n", encoding="ascii")
        real_open = os.open
        requested_flags: list[int] = []
        swapped = False

        def swap_to_fifo(
            path: os.PathLike[str] | str,
            flags: int,
            *args: object,
            **kwargs: object,
        ) -> int:
            nonlocal swapped
            if pathlib.Path(path) == node_extra_ca and not swapped:
                swapped = True
                node_extra_ca.unlink()
                os.mkfifo(node_extra_ca, mode=0o600)
                requested_flags.append(flags)
                flags |= os.O_NONBLOCK
            return real_open(path, flags, *args, **kwargs)

        with (
            mock.patch.object(
                named_lane_runtime.os,
                "open",
                side_effect=swap_to_fifo,
            ),
            self.assertRaisesRegex(
                NamedLaneGuardError,
                "changed during validation",
            ),
        ):
            named_lane_runtime._validate_node_extra_ca_certs(node_extra_ca)

        self.assertTrue(swapped)
        self.assertEqual(len(requested_flags), 1)
        self.assertNotEqual(requested_flags[0] & os.O_NONBLOCK, 0)

    def test_stream_limit_accepts_exact_limit_and_rejects_one_more_byte(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        for size, should_pass in ((4, True), (5, False)):
            with self.subTest(size=size):
                executable = self.make_executable(
                    f"import sys\nsys.stdout.buffer.write(b'x' * {size})\n"
                )
                stdout = self.root / f"stdout-{size}.bin"
                stderr = self.root / f"stderr-{size}.bin"
                if should_pass:
                    result = self.run_claude(
                        worktree=self.repo.resolve(),
                        stdout_path=stdout,
                        stderr_path=stderr,
                        command=(str(executable),),
                        prompt=b"",
                        timeout_seconds=2.0,
                        stream_limit_bytes=4,
                    )
                    self.assertEqual(result["stdout_bytes"], 4)
                else:
                    with self.assertRaises(ReviewOutputLimitError):
                        self.run_claude(
                            worktree=self.repo.resolve(),
                            stdout_path=stdout,
                            stderr_path=stderr,
                            command=(str(executable),),
                            prompt=b"",
                            timeout_seconds=2.0,
                            stream_limit_bytes=4,
                        )
                    self.assertFalse(stdout.exists())
                    self.assertFalse(stderr.exists())

    @unittest.skipUnless(os.name == "posix", "process-group test requires POSIX")
    def test_timeout_cleans_a_term_resistant_process_group(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable(
            "import signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "while True:\n"
            "    time.sleep(0.05)\n"
        )
        started = time.monotonic()

        with self.assertRaises(ReviewTimeoutError):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "timeout.out",
                stderr_path=self.root / "timeout.err",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=0.1,
                stream_limit_bytes=64,
            )

        self.assertLess(time.monotonic() - started, 3.0)
        self.assertEqual(tuple(self.root.glob(".named-lane-*")), ())

    @unittest.skipUnless(os.name == "posix", "detached-process test requires POSIX")
    def test_process_supervisor_does_not_claim_detached_tree_containment(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        pid_path = self.root / "detached.pid"
        executable = self.make_executable(
            "import os, pathlib, time\n"
            "ready_read, ready_write = os.pipe()\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os.close(ready_write)\n"
            "    if os.read(ready_read, 1) != b'1':\n"
            "        os._exit(1)\n"
            "    os.close(ready_read)\n"
            "    os.setsid()\n"
            "    for descriptor in (0, 1, 2):\n"
            "        try:\n"
            "            os.close(descriptor)\n"
            "        except OSError:\n"
            "            pass\n"
            "    time.sleep(30)\n"
            "    os._exit(0)\n"
            "os.close(ready_read)\n"
            f"pid_path = pathlib.Path({str(pid_path)!r})\n"
            "temporary_path = pid_path.with_suffix('.tmp')\n"
            "temporary_path.write_text(str(pid), encoding='ascii')\n"
            "os.replace(temporary_path, pid_path)\n"
            "os.write(ready_write, b'1')\n"
            "os.close(ready_write)\n"
            "os._exit(0)\n"
        )
        detached_pid: int | None = None
        try:
            result = self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "detached.out",
                stderr_path=self.root / "detached.err",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=64,
            )
            self.assertTrue(pid_path.exists())
            detached_pid = int(pid_path.read_text(encoding="ascii"))
            os.kill(detached_pid, 0)
            self.assertEqual(result["status"], "complete")
        finally:
            if detached_pid is None:
                try:
                    detached_pid = int(pid_path.read_text(encoding="ascii"))
                except FileNotFoundError:
                    pass
            if detached_pid is not None:
                try:
                    os.kill(detached_pid, 9)
                except ProcessLookupError:
                    pass

    def test_process_rejects_output_inside_worktree_and_nonexact_executable(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("pass\n")

        with self.assertRaisesRegex(NamedLaneGuardError, "outside the worktree"):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.repo / "stdout",
                stderr_path=self.root / "stderr",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=1.0,
                stream_limit_bytes=64,
            )
        with self.assertRaisesRegex(NamedLaneGuardError, "must be absolute"):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "stdout",
                stderr_path=self.root / "stderr",
                command=(executable.name,),
                prompt=b"",
                timeout_seconds=1.0,
                stream_limit_bytes=64,
            )

    def test_process_rejects_dangling_output_leaf_and_symlink_parent(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("pass\n")
        dangling = self.root / "dangling-output"
        dangling.symlink_to(self.root / "missing-target")

        with self.assertRaisesRegex(NamedLaneGuardError, "already exist"):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=dangling,
                stderr_path=self.root / "dangling.err",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=1.0,
                stream_limit_bytes=64,
            )

        real_parent = self.root / "real-output"
        real_parent.mkdir()
        linked_parent = self.root / "linked-output"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaisesRegex(
            NamedLaneGuardError, "real directory|traverse a symlink"
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=linked_parent / "stdout",
                stderr_path=self.root / "linked.err",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=1.0,
                stream_limit_bytes=64,
            )

        real_ancestor = self.root / "real-ancestor"
        nested_parent = real_ancestor / "nested"
        nested_parent.mkdir(parents=True)
        linked_ancestor = self.root / "linked-ancestor"
        linked_ancestor.symlink_to(real_ancestor, target_is_directory=True)
        with self.assertRaisesRegex(NamedLaneGuardError, "traverse a symlink"):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=linked_ancestor / "nested" / "stdout",
                stderr_path=self.root / "ancestor.err",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=1.0,
                stream_limit_bytes=64,
            )

    def test_process_rejects_nonprivate_output_parent(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("pass\n")
        output_parent = self.root / "shared-output"
        output_parent.mkdir(mode=0o755)
        output_parent.chmod(0o755)

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "current-user-owned with mode 0700",
        ):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=output_parent / "stdout",
                stderr_path=output_parent / "stderr",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=1.0,
                stream_limit_bytes=64,
            )

    def test_output_parent_mode_drift_blocks_publication(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        output_parent = self.root / "private-output"
        output_parent.mkdir(mode=0o700)
        output_parent.chmod(0o700)
        executable = self.make_executable(
            "import os, pathlib\n"
            f"os.chmod(pathlib.Path({str(output_parent)!r}), 0o755)\n"
        )

        try:
            with self.assertRaisesRegex(
                NamedLaneGuardError,
                "changed after validation",
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=output_parent / "stdout",
                    stderr_path=output_parent / "stderr",
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=64,
                )
        finally:
            output_parent.chmod(0o700)

        self.assertFalse((output_parent / "stdout").exists())
        self.assertFalse((output_parent / "stderr").exists())
        self.assertEqual(tuple(output_parent.glob(".named-lane-launch-*")), ())

    def test_process_anchors_outputs_if_parent_is_replaced_after_launch(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        output_parent = self.root / "outputs"
        displaced_parent = self.root / "outputs-displaced"
        output_parent.mkdir(mode=0o700)
        output_parent.chmod(0o700)
        executable = self.make_executable(
            "import os, pathlib, sys\n"
            f"parent = pathlib.Path({str(output_parent)!r})\n"
            f"displaced = pathlib.Path({str(displaced_parent)!r})\n"
            f"redirect = pathlib.Path({str(self.repo)!r})\n"
            "os.rename(parent, displaced)\n"
            "os.symlink(redirect, parent, target_is_directory=True)\n"
            "sys.stdout.write('captured stdout')\n"
            "sys.stderr.write('captured stderr')\n"
        )

        with self.assertRaisesRegex(NamedLaneGuardError, "changed after validation"):
            self.run_claude(
                worktree=self.repo.resolve(),
                stdout_path=output_parent / "stdout.bin",
                stderr_path=output_parent / "stderr.bin",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=64,
            )

        self.assertTrue(output_parent.is_symlink())
        self.assertFalse((self.repo / "stdout.bin").exists())
        self.assertFalse((self.repo / "stderr.bin").exists())
        self.assertFalse((displaced_parent / "stdout.bin").exists())
        self.assertFalse((displaced_parent / "stderr.bin").exists())
        self.assertEqual(
            tuple(displaced_parent.glob(".named-lane-launch-*")),
            (),
        )

    def test_snapshot_cleanup_reports_descriptor_locator_after_parent_move(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        output_parent = self.root / "locator-outputs"
        displaced_parent = self.root / "locator-outputs-displaced"
        output_parent.mkdir(mode=0o700)
        output_parent.chmod(0o700)
        executable = self.make_executable(
            "import os, pathlib\n"
            f"parent = pathlib.Path({str(output_parent)!r})\n"
            f"displaced = pathlib.Path({str(displaced_parent)!r})\n"
            f"redirect = pathlib.Path({str(self.repo)!r})\n"
            "os.rename(parent, displaced)\n"
            "os.symlink(redirect, parent, target_is_directory=True)\n"
        )
        real_unlink = named_lane_runtime._unlink_output_if_observed_same

        def fail_snapshot_cleanup(
            target: object,
            name: str,
            identity: tuple[int, int],
            *,
            label: str,
        ) -> None:
            if label == "Claude launch snapshot":
                raise NamedLaneGuardError("synthetic snapshot cleanup failure")
            real_unlink(target, name, identity, label=label)

        retained: pathlib.Path | None = None
        try:
            with (
                mock.patch.object(
                    named_lane_runtime,
                    "_unlink_output_if_observed_same",
                    side_effect=fail_snapshot_cleanup,
                ),
                self.assertRaises(
                    named_lane_runtime._ClaudeLaunchSnapshotCleanupError
                ) as context,
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=output_parent / "stdout.bin",
                    stderr_path=output_parent / "stderr.bin",
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=64,
                )

            error = context.exception
            displaced_metadata = displaced_parent.stat()
            self.assertIsNone(error.retained_path)
            self.assertEqual(error.process_reason, "complete")
            self.assertEqual(
                error.retained_parent_identity,
                (displaced_metadata.st_dev, displaced_metadata.st_ino),
            )
            self.assertIsNotNone(error.retained_leaf)
            retained = displaced_parent / error.retained_leaf
            self.assertTrue(retained.exists())
        finally:
            if retained is not None:
                retained.unlink(missing_ok=True)

        self.assertFalse((self.repo / "stdout.bin").exists())
        self.assertFalse((self.repo / "stderr.bin").exists())

    def test_output_temp_cleanup_failure_rolls_back_published_leaf(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("print('captured')\n")
        stdout = self.root / "cleanup-stdout.bin"
        stderr = self.root / "cleanup-stderr.bin"
        real_unlink = os.unlink
        failed_once = False

        def fail_first_temp_cleanup(
            path: str | bytes,
            *arguments: object,
            **keywords: object,
        ) -> None:
            nonlocal failed_once
            if (
                not failed_once
                and isinstance(path, str)
                and path.startswith(".named-lane-")
                and not path.startswith(".named-lane-launch-")
            ):
                failed_once = True
                raise OSError("synthetic temporary cleanup failure")
            real_unlink(path, *arguments, **keywords)

        with mock.patch(
            "review_runtime.named_lane.os.unlink",
            side_effect=fail_first_temp_cleanup,
        ):
            with self.assertRaisesRegex(
                NamedLaneGuardError, "temporary cleanup failed"
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=stdout,
                    stderr_path=stderr,
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=5.0,
                    stream_limit_bytes=64,
                )

        self.assertTrue(failed_once)
        self.assertFalse(stdout.exists())
        self.assertFalse(stderr.exists())
        self.assertEqual(list(self.root.glob(".named-lane-*")), [])

    def test_initial_output_fstat_failure_removes_temporary_leaf(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("print('captured')\n")
        stdout = self.root / "fstat-stdout.bin"
        stderr = self.root / "fstat-stderr.bin"
        real_fstat = os.fstat
        failed_once = False

        def fail_temporary_fstat(descriptor: int) -> os.stat_result:
            nonlocal failed_once
            output_temporaries = tuple(
                path
                for path in self.root.glob(".named-lane-*")
                if not path.name.startswith(".named-lane-launch-")
            )
            if not failed_once and output_temporaries:
                failed_once = True
                raise OSError("synthetic temporary fstat failure")
            return real_fstat(descriptor)

        with mock.patch.object(
            named_lane_runtime.os,
            "fstat",
            side_effect=fail_temporary_fstat,
        ):
            with self.assertRaisesRegex(
                NamedLaneGuardError,
                "temporary file cannot be inspected safely",
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=stdout,
                    stderr_path=stderr,
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=5.0,
                    stream_limit_bytes=64,
                )

        self.assertTrue(failed_once)
        self.assertFalse(stdout.exists())
        self.assertFalse(stderr.exists())
        self.assertEqual(list(self.root.glob(".named-lane-*")), [])

    def test_persistent_output_fstat_failure_retains_unverified_temporary_leaf(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("print('captured')\n")
        stdout = self.root / "persistent-fstat-stdout.bin"
        stderr = self.root / "persistent-fstat-stderr.bin"
        real_fstat = os.fstat
        failure_count = 0

        def fail_stderr_temporary_fstat(descriptor: int) -> os.stat_result:
            nonlocal failure_count
            if stdout.exists() and list(self.root.glob(".named-lane-*")):
                failure_count += 1
                raise OSError("synthetic persistent temporary fstat failure")
            return real_fstat(descriptor)

        retained_path: pathlib.Path | None = None
        try:
            with mock.patch.object(
                named_lane_runtime.os,
                "fstat",
                side_effect=fail_stderr_temporary_fstat,
            ):
                with self.assertRaisesRegex(
                    NamedLaneGuardError,
                    "temporary cleanup remained incomplete",
                ) as context:
                    self.run_claude(
                        worktree=self.repo.resolve(),
                        stdout_path=stdout,
                        stderr_path=stderr,
                        command=(str(executable),),
                        prompt=b"",
                        timeout_seconds=2.0,
                        stream_limit_bytes=64,
                    )

            retained = list(self.root.glob(".named-lane-*"))
            self.assertEqual(failure_count, 2)
            self.assertEqual(len(retained), 1)
            retained_path = retained[0]
            self.assertIn(
                f"retained Claude output temporary path: {retained_path}",
                str(context.exception),
            )
            self.assertFalse(stdout.exists())
            self.assertFalse(stderr.exists())
        finally:
            if retained_path is not None:
                retained_path.unlink(missing_ok=True)

    def test_output_publication_requires_signal_mask_before_writing(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("print('captured')\n")
        stdout = self.root / "mask-stdout.bin"
        stderr = self.root / "mask-stderr.bin"

        with mock.patch.object(
            named_lane_runtime,
            "block_forwarded_signals",
            return_value=None,
        ):
            with self.assertRaisesRegex(
                NamedLaneGuardError,
                "requires main-thread signal masking",
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=stdout,
                    stderr_path=stderr,
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=64,
                )

        self.assertFalse(stdout.exists())
        self.assertFalse(stderr.exists())

    def test_deferred_signal_rolls_back_complete_output_pair(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable(
            "import sys\n"
            "sys.stdout.write('captured stdout')\n"
            "sys.stderr.write('captured stderr')\n"
        )
        stdout = self.root / "signal-stdout.bin"
        stderr = self.root / "signal-stderr.bin"

        consume_calls = 0

        def consume_after_pair() -> signal.Signals | None:
            nonlocal consume_calls
            consume_calls += 1
            if consume_calls == 1:
                self.assertEqual(stdout.read_bytes(), b"captured stdout")
                self.assertEqual(stderr.read_bytes(), b"captured stderr")
                return signal.SIGINT
            return None

        with (
            mock.patch.object(
                named_lane_runtime,
                "block_forwarded_signals",
                return_value=set(),
            ),
            mock.patch.object(
                named_lane_runtime,
                "consume_pending_forwarded_signal",
                side_effect=consume_after_pair,
            ),
            mock.patch.object(
                named_lane_runtime,
                "restore_signal_mask",
            ) as restore,
        ):
            with self.assertRaises(ForwardedSignal) as raised:
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=stdout,
                    stderr_path=stderr,
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=64,
                )

        self.assertEqual(raised.exception.signum, signal.SIGINT)
        self.assertFalse(stdout.exists())
        self.assertFalse(stderr.exists())
        self.assertEqual(restore.call_args_list, [mock.call(set())] * 3)

    def test_keyboard_interrupt_rolls_back_first_published_output(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("print('captured')\n")
        stdout = self.root / "interrupt-stdout.bin"
        stderr = self.root / "interrupt-stderr.bin"
        real_write = named_lane_runtime._write_private_bytes
        calls = 0

        def interrupt_second_write(
            target: object,
            payload: bytes | bytearray,
        ) -> object:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise KeyboardInterrupt
            return real_write(target, payload)

        with mock.patch.object(
            named_lane_runtime,
            "_write_private_bytes",
            side_effect=interrupt_second_write,
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=stdout,
                    stderr_path=stderr,
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=64,
                )

        self.assertEqual(calls, 2)
        self.assertFalse(stdout.exists())
        self.assertFalse(stderr.exists())

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "signal publication test requires POSIX signal masks",
    )
    def test_signal_during_mask_restore_rolls_back_output_pair(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable(
            "import sys\n"
            "sys.stdout.write('captured stdout')\n"
            "sys.stderr.write('captured stderr')\n"
        )
        stdout = self.root / "restore-signal-stdout.bin"
        stderr = self.root / "restore-signal-stderr.bin"
        previous_handler = signal.getsignal(signal.SIGINT)
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        real_restore = named_lane_runtime.restore_signal_mask
        consume_calls = 0
        restore_calls = 0

        def consume_after_pair() -> None:
            nonlocal consume_calls
            consume_calls += 1
            if consume_calls == 1:
                self.assertEqual(stdout.read_bytes(), b"captured stdout")
                self.assertEqual(stderr.read_bytes(), b"captured stderr")
            return None

        def interrupt_publication_restore(mask: set[signal.Signals]) -> None:
            nonlocal restore_calls
            restore_calls += 1
            real_restore(mask)
            if restore_calls == 3:
                temporary_handler = signal.getsignal(signal.SIGINT)
                self.assertIsNot(temporary_handler, previous_handler)
                self.assertTrue(callable(temporary_handler))
                temporary_handler(signal.SIGINT, None)

        with (
            mock.patch.object(
                named_lane_runtime,
                "consume_pending_forwarded_signal",
                side_effect=consume_after_pair,
            ),
            mock.patch.object(
                named_lane_runtime,
                "restore_signal_mask",
                side_effect=interrupt_publication_restore,
            ),
        ):
            with self.assertRaises(ForwardedSignal) as raised:
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=stdout,
                    stderr_path=stderr,
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=64,
                )

        self.assertEqual(raised.exception.signum, signal.SIGINT)
        self.assertGreaterEqual(consume_calls, 2)
        self.assertEqual(restore_calls, 4)
        self.assertFalse(stdout.exists())
        self.assertFalse(stderr.exists())
        self.assertEqual(signal.getsignal(signal.SIGINT), previous_handler)
        self.assertEqual(
            signal.pthread_sigmask(signal.SIG_BLOCK, set()),
            previous_mask,
        )

    def test_output_rollback_preserves_replacement_observed_before_cleanup(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("print('captured')\n")
        stdout = self.root / "replacement-stdout.bin"
        stderr = self.root / "replacement-stderr.bin"
        replacement = self.root / "replacement-source.bin"
        replacement.write_bytes(b"concurrent replacement")
        real_write = named_lane_runtime._write_private_bytes
        calls = 0

        def replace_before_second_failure(
            target: object,
            payload: bytes | bytearray,
        ) -> object:
            nonlocal calls
            calls += 1
            if calls == 1:
                output = real_write(target, payload)
                os.replace(replacement, stdout)
                return output
            raise NamedLaneGuardError("synthetic stderr publication failure")

        with mock.patch.object(
            named_lane_runtime,
            "_write_private_bytes",
            side_effect=replace_before_second_failure,
        ):
            with self.assertRaisesRegex(
                NamedLaneGuardError,
                "rollback remained incomplete",
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=stdout,
                    stderr_path=stderr,
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=64,
                )

        self.assertEqual(stdout.read_bytes(), b"concurrent replacement")
        self.assertFalse(stderr.exists())

    def test_temp_cleanup_preserves_replacement_observed_before_rollback(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable("print('captured')\n")
        stdout = self.root / "temp-replacement-stdout.bin"
        stderr = self.root / "temp-replacement-stderr.bin"
        replacement = self.root / "temp-replacement-source.bin"
        replacement.write_bytes(b"concurrent replacement")
        real_unlink = os.unlink
        failed_once = False

        def replace_before_temp_cleanup_failure(
            path: str | bytes,
            *arguments: object,
            **keywords: object,
        ) -> None:
            nonlocal failed_once
            if (
                not failed_once
                and isinstance(path, str)
                and path.startswith(".named-lane-")
                and not path.startswith(".named-lane-launch-")
            ):
                failed_once = True
                os.replace(replacement, stdout)
                raise OSError("synthetic temporary cleanup failure")
            real_unlink(path, *arguments, **keywords)

        with mock.patch.object(
            named_lane_runtime.os,
            "unlink",
            side_effect=replace_before_temp_cleanup_failure,
        ):
            with self.assertRaisesRegex(
                NamedLaneGuardError,
                "cleanup or rollback remained incomplete",
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=stdout,
                    stderr_path=stderr,
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=2.0,
                    stream_limit_bytes=64,
                )

        self.assertTrue(failed_once)
        self.assertEqual(stdout.read_bytes(), b"concurrent replacement")
        self.assertFalse(stderr.exists())
        self.assertEqual(list(self.root.glob(".named-lane-*")), [])

    def test_cli_prompt_read_times_out_when_writer_withholds_eof(self) -> None:
        marker = self.root / "prompt-reviewer-started.marker"
        executable = self.make_executable(
            f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
        )
        stdout_path = self.root / "prompt-timeout.stdout"
        stderr_path = self.root / "prompt-timeout.stderr"
        started = time.monotonic()
        process = subprocess.Popen(
            self.isolated_guard_command(
                SCRIPTS / "named_lane_guard",
                "run-claude",
                "--worktree",
                str(self.repo.resolve()),
                "--source-worktree",
                str(self.source_control),
                "--preflight-result",
                str(self.preflight_result_path(executable)),
                "--stdout-path",
                str(stdout_path),
                "--stderr-path",
                str(stderr_path),
                "--timeout-seconds",
                "0.05",
                "--",
                str(executable),
            ),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert process.stdin is not None
            process.stdin.write(b"short prompt")
            process.stdin.flush()
            returncode = process.wait(timeout=2.0)
            assert process.stdout is not None
            assert process.stderr is not None
            stdout = process.stdout.read()
            stderr = process.stderr.read()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2.0)
            if process.stdin is not None:
                process.stdin.close()
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(returncode, 2)
        self.assertEqual(stdout, b"")
        self.assertEqual(
            json.loads(stderr),
            {"status": "inconclusive", "reason": "deadline"},
        )
        self.assertFalse(marker.exists())
        self.assertFalse(stdout_path.exists())
        self.assertFalse(stderr_path.exists())

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "structured prompt signals require POSIX signal masks",
    )
    def test_cli_prompt_read_classifies_and_restores_forwarded_signals(
        self,
    ) -> None:
        argv = (
            "run-claude",
            "--worktree",
            str(self.repo.resolve()),
            "--source-worktree",
            str(self.source_control),
            "--preflight-result",
            str(self.root / "unused-prompt-signal-preflight.json"),
            "--stdout-path",
            str(self.root / "prompt-signal.stdout"),
            "--stderr-path",
            str(self.root / "prompt-signal.stderr"),
            "--timeout-seconds",
            "5",
            "--",
            "/usr/bin/false",
        )

        for forwarded in named_lane_runtime.forwarded_signals():
            with self.subTest(signal=forwarded):
                previous_handlers = {
                    candidate: signal.getsignal(candidate)
                    for candidate in named_lane_runtime.forwarded_signals()
                }
                previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
                stdout = io.StringIO()
                stderr = io.StringIO()

                def interrupt_prompt(*_arguments: object) -> bytes:
                    handler = signal.getsignal(forwarded)
                    self.assertTrue(callable(handler))
                    handler(int(forwarded), None)
                    self.fail("forwarded signal handler returned")

                with (
                    mock.patch.object(
                        named_lane_runtime,
                        "_read_control_prompt",
                        side_effect=interrupt_prompt,
                    ),
                    mock.patch.object(named_lane_runtime, "run_claude") as run,
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    returncode = self.named_lane_main(argv)

                self.assertEqual(returncode, 128 + int(forwarded))
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(
                    json.loads(stderr.getvalue()),
                    {"status": "inconclusive", "reason": "forwarded-signal"},
                )
                run.assert_not_called()
                for candidate, previous in previous_handlers.items():
                    self.assertEqual(signal.getsignal(candidate), previous)
                self.assertEqual(
                    signal.pthread_sigmask(signal.SIG_BLOCK, set()),
                    previous_mask,
                )
                self.assertFalse((self.root / "prompt-signal.stdout").exists())
                self.assertFalse((self.root / "prompt-signal.stderr").exists())

    def test_cli_prompt_read_shares_deadline_with_process(self) -> None:
        result = {"status": "complete"}

        def complete_with_receipt(**kwargs: object) -> dict[str, object]:
            receipt_emitter = kwargs["_receipt_emitter"]
            self.assertTrue(callable(receipt_emitter))
            receipt_emitter(result)
            return result

        with (
            mock.patch.object(
                named_lane_runtime.time,
                "monotonic",
                side_effect=(100.0, 101.5),
            ),
            mock.patch.object(
                named_lane_runtime,
                "_read_control_prompt",
                return_value=b"review",
            ) as prompt_read,
            mock.patch.object(
                named_lane_runtime,
                "run_claude",
                side_effect=complete_with_receipt,
            ) as run,
            mock.patch.object(named_lane_runtime, "_emit") as emit,
        ):
            returncode = self.named_lane_main(
                (
                    "run-claude",
                    "--worktree",
                    str(self.repo.resolve()),
                    "--source-worktree",
                    str(self.source_control),
                    "--preflight-result",
                    str(self.root / "unused-prompt-budget-preflight.json"),
                    "--stdout-path",
                    str(self.root / "prompt-budget.stdout"),
                    "--stderr-path",
                    str(self.root / "prompt-budget.stderr"),
                    "--timeout-seconds",
                    "5",
                    "--",
                    "/usr/bin/false",
                )
            )

        self.assertEqual(returncode, 0)
        emit.assert_called_once_with(result)
        self.assertEqual(prompt_read.call_args.args[1:], (256 * 1024, 105.0))
        self.assertEqual(run.call_args.kwargs["prompt"], b"review")
        self.assertEqual(
            run.call_args.kwargs["preflight_result"],
            self.root / "unused-prompt-budget-preflight.json",
        )
        self.assertEqual(run.call_args.kwargs["timeout_seconds"], 3.5)
        self.assertEqual(run.call_args.kwargs["deadline_monotonic"], 105.0)

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "receipt handoff requires POSIX signal masks",
    )
    def test_cli_receipt_failure_rolls_back_output_pair(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable(
            "import sys\n"
            "sys.stdout.write('captured stdout')\n"
            "sys.stderr.write('captured stderr')\n"
        )
        preflight = self.preflight_result_path(executable)
        real_emit = named_lane_runtime._emit

        cases = (
            ("write-error", OSError("synthetic receipt failure"), 2),
            (
                "forwarded-signal",
                ForwardedSignal(signal.SIGTERM),
                128 + signal.SIGTERM,
            ),
        )
        for label, receipt_error, expected_returncode in cases:
            with self.subTest(label=label):
                stdout_path = self.root / f"{label}-receipt.stdout"
                stderr_path = self.root / f"{label}-receipt.stderr"
                stdout = io.StringIO()
                stderr = io.StringIO()
                previous_handlers = {
                    forwarded: signal.getsignal(forwarded)
                    for forwarded in named_lane_runtime.forwarded_signals()
                }
                previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())

                def fail_process_receipt(
                    payload: dict[str, object],
                    *,
                    stream: object | None = None,
                ) -> None:
                    if "launch_binding" in payload:
                        raise receipt_error
                    real_emit(payload, stream=stream)

                with (
                    mock.patch.object(
                        named_lane_runtime,
                        "_read_control_prompt",
                        return_value=b"",
                    ),
                    mock.patch.object(
                        named_lane_runtime,
                        "_emit",
                        side_effect=fail_process_receipt,
                    ),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    returncode = self.named_lane_main(
                        (
                            "run-claude",
                            "--worktree",
                            str(self.repo.resolve()),
                            "--source-worktree",
                            str(self.source_control),
                            "--preflight-result",
                            str(preflight),
                            "--stdout-path",
                            str(stdout_path),
                            "--stderr-path",
                            str(stderr_path),
                            "--timeout-seconds",
                            "5",
                            "--",
                            str(executable),
                        )
                    )

                self.assertEqual(returncode, expected_returncode)
                self.assertEqual(stdout.getvalue(), "")
                failure = json.loads(stderr.getvalue())
                self.assertEqual(failure["status"], "inconclusive")
                if isinstance(receipt_error, ForwardedSignal):
                    self.assertEqual(failure["reason"], "forwarded-signal")
                else:
                    self.assertIn("synthetic receipt failure", failure["reason"])
                self.assertFalse(stdout_path.exists())
                self.assertFalse(stderr_path.exists())
                self.assertEqual(tuple(self.root.glob(".named-lane-*")), ())
                for forwarded, previous in previous_handlers.items():
                    self.assertEqual(signal.getsignal(forwarded), previous)
                self.assertEqual(
                    signal.pthread_sigmask(signal.SIG_BLOCK, set()),
                    previous_mask,
                )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "receipt handoff requires POSIX signal masks",
    )
    def test_signal_during_receipt_emission_rolls_back_output_pair(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable(
            "import sys\n"
            "sys.stdout.write('captured stdout')\n"
            "sys.stderr.write('captured stderr')\n"
        )
        stdout_path = self.root / "receipt-signal.stdout"
        stderr_path = self.root / "receipt-signal.stderr"
        previous_handlers = {
            forwarded: signal.getsignal(forwarded)
            for forwarded in named_lane_runtime.forwarded_signals()
        }
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        receipt_stdout = io.StringIO()

        def interrupt_receipt(payload: dict[str, object]) -> None:
            self.assertEqual(stdout_path.read_bytes(), b"captured stdout")
            self.assertEqual(stderr_path.read_bytes(), b"captured stderr")
            signal.raise_signal(signal.SIGTERM)
            named_lane_runtime._emit_claude_receipt(payload)

        with contextlib.redirect_stdout(receipt_stdout):
            with self.assertRaises(ForwardedSignal) as raised:
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    command=(str(executable),),
                    prompt=b"",
                    timeout_seconds=5,
                    stream_limit_bytes=64,
                    _receipt_emitter=interrupt_receipt,
                )

        self.assertEqual(raised.exception.signum, signal.SIGTERM)
        self.assertEqual(json.loads(receipt_stdout.getvalue())["status"], "complete")
        self.assertFalse(stdout_path.exists())
        self.assertFalse(stderr_path.exists())
        self.assertEqual(tuple(self.root.glob(".named-lane-*")), ())
        for forwarded, previous in previous_handlers.items():
            self.assertEqual(signal.getsignal(forwarded), previous)
        self.assertEqual(
            signal.pthread_sigmask(signal.SIG_BLOCK, set()),
            previous_mask,
        )

    @unittest.skipUnless(
        os.name == "posix" and hasattr(signal, "pthread_sigmask"),
        "receipt handoff requires POSIX signal masks",
    )
    def test_cli_signal_after_flushed_receipt_keeps_output_pair(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        self.commit()
        executable = self.make_executable(
            "import sys\n"
            "sys.stdout.write('captured stdout')\n"
            "sys.stderr.write('captured stderr')\n"
        )
        stdout_path = self.root / "flushed-receipt.stdout"
        stderr_path = self.root / "flushed-receipt.stderr"
        preflight = self.preflight_result_path(executable)
        previous_handlers = {
            forwarded: signal.getsignal(forwarded)
            for forwarded in named_lane_runtime.forwarded_signals()
        }
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        real_install = named_lane_runtime._install_post_terminal_signal_handlers

        class SignalAfterFlush(io.StringIO):
            flush_calls = 0

            def flush(inner_self) -> None:
                super().flush()
                inner_self.flush_calls += 1

        def signal_after_receipt_commit() -> list[signal.Signals]:
            self.assertEqual(stdout.flush_calls, 1)
            recorded = real_install()
            signal.raise_signal(signal.SIGTERM)
            return recorded

        stdout = SignalAfterFlush()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                named_lane_runtime,
                "_read_control_prompt",
                return_value=b"",
            ),
            mock.patch.object(
                named_lane_runtime,
                "_install_post_terminal_signal_handlers",
                side_effect=signal_after_receipt_commit,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(
                (
                    "run-claude",
                    "--worktree",
                    str(self.repo.resolve()),
                    "--source-worktree",
                    str(self.source_control),
                    "--preflight-result",
                    str(preflight),
                    "--stdout-path",
                    str(stdout_path),
                    "--stderr-path",
                    str(stderr_path),
                    "--timeout-seconds",
                    "5",
                    "--",
                    str(executable),
                )
            )

        self.assertEqual(returncode, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(stdout.flush_calls, 1)
        receipt = json.loads(stdout.getvalue())
        self.assertEqual(receipt["status"], "complete")
        self.assertEqual(receipt["launch_binding"]["mode"], "verified-snapshot")
        self.assertEqual(stdout_path.read_bytes(), b"captured stdout")
        self.assertEqual(stderr_path.read_bytes(), b"captured stderr")
        for forwarded, previous in previous_handlers.items():
            self.assertEqual(signal.getsignal(forwarded), previous)
        self.assertEqual(
            signal.pthread_sigmask(signal.SIG_BLOCK, set()),
            previous_mask,
        )

    def test_worktree_git_resolution_uses_shared_remaining_deadline(self) -> None:
        observed_timeouts: list[float] = []

        def slow_git(
            _root: pathlib.Path,
            _arguments: object,
            *,
            timeout_seconds: float,
            **_keywords: object,
        ) -> bytes:
            observed_timeouts.append(timeout_seconds)
            raise ReviewTimeoutError("synthetic slow Git resolution")

        with (
            mock.patch.object(
                named_lane_runtime.time,
                "monotonic",
                side_effect=(100.0, 100.0, 104.5),
            ),
            mock.patch.object(
                named_lane_runtime,
                "_git_capture",
                side_effect=slow_git,
            ),
        ):
            with self.assertRaisesRegex(
                ReviewTimeoutError,
                "synthetic slow Git resolution",
            ):
                self.run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=self.root / "git-deadline.stdout",
                    stderr_path=self.root / "git-deadline.stderr",
                    command=("/usr/bin/false",),
                    prompt=b"review",
                    timeout_seconds=5.0,
                    stream_limit_bytes=64,
                    deadline_monotonic=105.0,
                )

        self.assertEqual(observed_timeouts, [0.5])
        self.assertFalse((self.root / "git-deadline.stdout").exists())
        self.assertFalse((self.root / "git-deadline.stderr").exists())

    def test_cli_rejects_resource_overrides_above_default_caps(self) -> None:
        cases = (
            (
                "timeout",
                (
                    "--timeout-seconds",
                    str(named_lane_runtime.DEFAULT_TIMEOUT_SECONDS + 1),
                ),
                "must not exceed",
            ),
            (
                "stream",
                (
                    "--stream-limit-bytes",
                    str(named_lane_runtime.DEFAULT_STREAM_LIMIT_BYTES + 1),
                ),
                "must not exceed",
            ),
            (
                "prompt",
                (
                    "--prompt-limit-bytes",
                    str(named_lane_runtime.DEFAULT_PROMPT_LIMIT_BYTES + 1),
                ),
                "must not exceed",
            ),
            ("timeout-nan", ("--timeout-seconds", "nan"), "positive and finite"),
            ("timeout-inf", ("--timeout-seconds", "inf"), "positive and finite"),
            ("timeout-neg-inf", ("--timeout-seconds=-inf",), "positive and finite"),
        )
        for label, override, expected_reason in cases:
            with self.subTest(label=label):
                stdout = io.StringIO()
                stderr = io.StringIO()
                argv = (
                    "run-claude",
                    "--worktree",
                    str(self.repo.resolve()),
                    "--source-worktree",
                    str(self.source_control),
                    "--preflight-result",
                    str(self.root / f"unused-{label}-cap-preflight.json"),
                    "--stdout-path",
                    str(self.root / f"{label}-cap.stdout"),
                    "--stderr-path",
                    str(self.root / f"{label}-cap.stderr"),
                    *override,
                    "--",
                    "/usr/bin/false",
                )
                with (
                    mock.patch.object(
                        named_lane_runtime,
                        "_read_control_prompt",
                    ) as prompt_read,
                    mock.patch.object(named_lane_runtime, "run_claude") as run,
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    returncode = self.named_lane_main(argv)

                self.assertEqual(returncode, 2)
                self.assertEqual(stdout.getvalue(), "")
                result = json.loads(stderr.getvalue())
                self.assertEqual(result["status"], "inconclusive")
                self.assertIn(expected_reason, result["reason"])
                prompt_read.assert_not_called()
                run.assert_not_called()

    def test_direct_claude_api_cannot_bypass_default_resource_caps(self) -> None:
        cases = (
            {
                "timeout_seconds": named_lane_runtime.DEFAULT_TIMEOUT_SECONDS + 1,
                "stream_limit_bytes": 64,
                "prompt": b"",
            },
            {
                "timeout_seconds": 1.0,
                "stream_limit_bytes": (
                    named_lane_runtime.DEFAULT_STREAM_LIMIT_BYTES + 1
                ),
                "prompt": b"",
            },
            {
                "timeout_seconds": 1.0,
                "stream_limit_bytes": 64,
                "prompt": b"x" * (named_lane_runtime.DEFAULT_PROMPT_LIMIT_BYTES + 1),
            },
        )
        with mock.patch.object(
            named_lane_runtime,
            "run_bounded_capture",
        ) as capture:
            for case in cases:
                with self.subTest(case=case):
                    with self.assertRaisesRegex(
                        NamedLaneGuardError,
                        "must not exceed",
                    ):
                        self.run_claude(
                            worktree=self.repo.resolve(),
                            stdout_path=self.root / "direct-cap.stdout",
                            stderr_path=self.root / "direct-cap.stderr",
                            command=("/usr/bin/false",),
                            **case,
                        )
            capture.assert_not_called()

    def test_absolute_deadline_can_only_tighten_duration_limit(self) -> None:
        with mock.patch.object(
            named_lane_runtime.time,
            "monotonic",
            return_value=100.0,
        ):
            self.assertEqual(
                named_lane_runtime._bounded_deadline(
                    named_lane_runtime.DEFAULT_TIMEOUT_SECONDS
                ),
                100.0 + named_lane_runtime.DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertEqual(
                named_lane_runtime._bounded_deadline(1.0, 1_000.0),
                101.0,
            )
            self.assertEqual(
                named_lane_runtime._bounded_deadline(10.0, 100.5),
                100.5,
            )
        self.assertEqual(
            named_lane_runtime._validate_byte_limit(
                named_lane_runtime.DEFAULT_STREAM_LIMIT_BYTES,
                named_lane_runtime.DEFAULT_STREAM_LIMIT_BYTES,
                "stream limit",
            ),
            named_lane_runtime.DEFAULT_STREAM_LIMIT_BYTES,
        )
        self.assertEqual(
            named_lane_runtime._validate_byte_limit(
                named_lane_runtime.DEFAULT_PROMPT_LIMIT_BYTES,
                named_lane_runtime.DEFAULT_PROMPT_LIMIT_BYTES,
                "prompt limit",
            ),
            named_lane_runtime.DEFAULT_PROMPT_LIMIT_BYTES,
        )

    def test_cli_reports_snapshot_cleanup_path_and_process_reason(self) -> None:
        retained = self.root / ".named-lane-launch-retained"
        stderr = io.StringIO()
        error = named_lane_runtime._ClaudeLaunchSnapshotCleanupError(
            retained,
            "deadline",
        )
        argv = (
            "run-claude",
            "--worktree",
            str(self.repo.resolve()),
            "--source-worktree",
            str(self.source_control),
            "--preflight-result",
            str(self.root / "unused-cleanup-preflight.json"),
            "--stdout-path",
            str(self.root / "unused-cleanup.stdout"),
            "--stderr-path",
            str(self.root / "unused-cleanup.stderr"),
            "--",
            "/usr/bin/false",
        )

        with (
            mock.patch.object(
                named_lane_runtime,
                "_read_control_prompt",
                return_value=b"",
            ),
            mock.patch.object(
                named_lane_runtime,
                "run_claude",
                side_effect=error,
            ),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(argv)

        self.assertEqual(returncode, 2)
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {
                "status": "inconclusive",
                "reason": "snapshot-cleanup",
                "process_reason": "deadline",
                "retained_path": str(retained),
            },
        )

    def test_cli_reports_descriptor_bound_snapshot_cleanup_locator(self) -> None:
        stderr = io.StringIO()
        error = named_lane_runtime._ClaudeLaunchSnapshotCleanupError(
            None,
            "complete",
            retained_parent_identity=(23, 47),
            retained_leaf=".named-lane-launch-retained",
        )
        argv = (
            "run-claude",
            "--worktree",
            str(self.repo.resolve()),
            "--source-worktree",
            str(self.source_control),
            "--preflight-result",
            str(self.root / "unused-locator-preflight.json"),
            "--stdout-path",
            str(self.root / "unused-locator.stdout"),
            "--stderr-path",
            str(self.root / "unused-locator.stderr"),
            "--",
            "/usr/bin/false",
        )

        with (
            mock.patch.object(
                named_lane_runtime,
                "_read_control_prompt",
                return_value=b"",
            ),
            mock.patch.object(
                named_lane_runtime,
                "run_claude",
                side_effect=error,
            ),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(argv)

        self.assertEqual(returncode, 2)
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {
                "status": "inconclusive",
                "reason": "snapshot-cleanup",
                "process_reason": "complete",
                "retained_locator": {
                    "parent_device": 23,
                    "parent_inode": 47,
                    "leaf": ".named-lane-launch-retained",
                },
            },
        )

    def test_cli_reports_descriptor_bound_session_env_cleanup_locator(self) -> None:
        stderr = io.StringIO()
        error = named_lane_runtime._ClaudeSessionEnvCleanupError(
            None,
            "complete",
            retained_parent_identity=(29, 53),
            retained_leaf="00000000-0000-4000-8000-000000000000",
            retained_leaf_identity=(31, 59),
        )
        argv = (
            "run-claude",
            "--worktree",
            str(self.repo.resolve()),
            "--source-worktree",
            str(self.source_control),
            "--preflight-result",
            str(self.root / "unused-session-cleanup-preflight.json"),
            "--stdout-path",
            str(self.root / "unused-session-cleanup.stdout"),
            "--stderr-path",
            str(self.root / "unused-session-cleanup.stderr"),
            "--",
            "/usr/bin/false",
        )

        with (
            mock.patch.object(
                named_lane_runtime,
                "_read_control_prompt",
                return_value=b"",
            ),
            mock.patch.object(
                named_lane_runtime,
                "run_claude",
                side_effect=error,
            ),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(argv)

        self.assertEqual(returncode, 2)
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {
                "status": "inconclusive",
                "reason": "session-env-cleanup",
                "process_reason": "complete",
                "retained_locator": {
                    "parent_device": 29,
                    "parent_inode": 53,
                    "leaf": "00000000-0000-4000-8000-000000000000",
                    "leaf_device": 31,
                    "leaf_inode": 59,
                },
            },
        )

    def test_cli_preserves_unquiescent_supervision_reason_with_session_locator(
        self,
    ) -> None:
        for process_reason in ("process-leak", "output-drain"):
            with self.subTest(process_reason=process_reason):
                stderr = io.StringIO()
                retained = self.root / "retained-unquiescent-session"
                error = named_lane_runtime._ClaudeSessionEnvCleanupError(
                    retained,
                    process_reason,
                    retained_parent_identity=(29, 53),
                    retained_leaf="00000000-0000-4000-8000-000000000000",
                    retained_leaf_identity=(31, 59),
                    retained_for_quiescence=True,
                )
                argv = (
                    "run-claude",
                    "--worktree",
                    str(self.repo.resolve()),
                    "--source-worktree",
                    str(self.source_control),
                    "--preflight-result",
                    str(self.root / "unused-unquiescent-preflight.json"),
                    "--stdout-path",
                    str(self.root / "unused-unquiescent.stdout"),
                    "--stderr-path",
                    str(self.root / "unused-unquiescent.stderr"),
                    "--",
                    "/usr/bin/false",
                )

                with (
                    mock.patch.object(
                        named_lane_runtime,
                        "_read_control_prompt",
                        return_value=b"",
                    ),
                    mock.patch.object(
                        named_lane_runtime,
                        "run_claude",
                        side_effect=error,
                    ),
                    contextlib.redirect_stderr(stderr),
                ):
                    returncode = self.named_lane_main(argv)

                self.assertEqual(returncode, 2)
                self.assertEqual(
                    json.loads(stderr.getvalue()),
                    {
                        "status": "inconclusive",
                        "reason": "process-leak",
                        "process_reason": process_reason,
                        "retained_path": str(retained),
                        "retained_locator": {
                            "parent_device": 29,
                            "parent_inode": 53,
                            "leaf": "00000000-0000-4000-8000-000000000000",
                            "leaf_device": 31,
                            "leaf_inode": 59,
                        },
                    },
                )

    def test_cli_reports_removed_session_env_with_parent_custody_drift(self) -> None:
        stderr = io.StringIO()
        error = named_lane_runtime._ClaudeSessionEnvCustodyError(
            "00000000-0000-4000-8000-000000000000",
            "parent-custody",
            parent_identity=(37, 61),
            leaf_identity=(41, 67),
        )
        argv = (
            "run-claude",
            "--worktree",
            str(self.repo.resolve()),
            "--source-worktree",
            str(self.source_control),
            "--preflight-result",
            str(self.root / "unused-session-custody-preflight.json"),
            "--stdout-path",
            str(self.root / "unused-session-custody.stdout"),
            "--stderr-path",
            str(self.root / "unused-session-custody.stderr"),
            "--",
            "/usr/bin/false",
        )

        with (
            mock.patch.object(
                named_lane_runtime,
                "_read_control_prompt",
                return_value=b"",
            ),
            mock.patch.object(
                named_lane_runtime,
                "run_claude",
                side_effect=error,
            ),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(argv)

        self.assertEqual(returncode, 2)
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {
                "status": "inconclusive",
                "reason": "session-env-custody",
                "process_reason": "parent-custody",
                "session_id": "00000000-0000-4000-8000-000000000000",
                "cleanup_status": "removed",
                "parent_identity": {"device": 37, "inode": 61},
                "leaf_identity": {"device": 41, "inode": 67},
            },
        )

    def test_cli_reports_both_control_cleanup_recovery_identities(self) -> None:
        stderr = io.StringIO()
        error = named_lane_runtime._ClaudeControlCleanupError(
            named_lane_runtime._ClaudeLaunchSnapshotCleanupError(
                None,
                "deadline",
                retained_parent_identity=(43, 71),
                retained_leaf=".named-lane-launch-retained",
            ),
            named_lane_runtime._ClaudeSessionEnvCleanupError(
                None,
                "deadline",
                retained_parent_identity=(47, 73),
                retained_leaf="00000000-0000-4000-8000-000000000000",
                retained_leaf_identity=(53, 79),
            ),
        )
        argv = (
            "run-claude",
            "--worktree",
            str(self.repo.resolve()),
            "--source-worktree",
            str(self.source_control),
            "--preflight-result",
            str(self.root / "unused-control-cleanup-preflight.json"),
            "--stdout-path",
            str(self.root / "unused-control-cleanup.stdout"),
            "--stderr-path",
            str(self.root / "unused-control-cleanup.stderr"),
            "--",
            "/usr/bin/false",
        )

        with (
            mock.patch.object(
                named_lane_runtime,
                "_read_control_prompt",
                return_value=b"",
            ),
            mock.patch.object(
                named_lane_runtime,
                "run_claude",
                side_effect=error,
            ),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(argv)

        self.assertEqual(returncode, 2)
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["reason"], "control-cleanup")
        self.assertEqual(payload["snapshot"]["retained_locator"]["parent_inode"], 71)
        self.assertEqual(payload["session_env"]["retained_locator"]["leaf_inode"], 79)

    def test_cli_process_leak_precedes_combined_control_cleanup(self) -> None:
        stderr = io.StringIO()
        error = named_lane_runtime._ClaudeControlCleanupError(
            named_lane_runtime._ClaudeLaunchSnapshotCleanupError(
                None,
                "output-drain",
                retained_parent_identity=(43, 71),
                retained_leaf=".named-lane-launch-retained",
            ),
            named_lane_runtime._ClaudeSessionEnvCleanupError(
                None,
                "output-drain",
                retained_parent_identity=(47, 73),
                retained_leaf="00000000-0000-4000-8000-000000000000",
                retained_leaf_identity=(53, 79),
                retained_for_quiescence=True,
            ),
        )
        argv = (
            "run-claude",
            "--worktree",
            str(self.repo.resolve()),
            "--source-worktree",
            str(self.source_control),
            "--preflight-result",
            str(self.root / "unused-process-leak-preflight.json"),
            "--stdout-path",
            str(self.root / "unused-process-leak.stdout"),
            "--stderr-path",
            str(self.root / "unused-process-leak.stderr"),
            "--",
            "/usr/bin/false",
        )

        with (
            mock.patch.object(
                named_lane_runtime,
                "_read_control_prompt",
                return_value=b"",
            ),
            mock.patch.object(
                named_lane_runtime,
                "run_claude",
                side_effect=error,
            ),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = self.named_lane_main(argv)

        self.assertEqual(returncode, 2)
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["reason"], "process-leak")
        self.assertEqual(payload["session_env"]["process_reason"], "output-drain")
        self.assertEqual(payload["session_env"]["retained_locator"]["leaf_inode"], 79)
        self.assertEqual(payload["snapshot"]["retained_locator"]["parent_inode"], 71)

    @retired_public_commands("materialize-worktree", "validate-worktree")
    def test_control_object_reason_is_stable_across_safety_commands(self) -> None:
        reason = "materialized-git-config-content-mismatch"
        error = named_lane_runtime._ControlObjectGuardError(
            reason,
            "human-readable control-object detail",
        )
        commands = (
            (
                "review_runtime.named_lane.materialize_worktree",
                (
                    "materialize-worktree",
                    "--source",
                    str(self.repo.resolve()),
                    "--worktree",
                    str(self.root / "control-reason-materialized-worktree"),
                    "--base",
                    "0" * 40,
                    "--head",
                    "0" * 40,
                ),
            ),
            (
                "review_runtime.named_lane.validate_worktree",
                (
                    "validate-worktree",
                    "--worktree",
                    str(self.repo.resolve()),
                    "--base",
                    "0" * 40,
                    "--head",
                    "0" * 40,
                ),
            ),
        )

        for target, argv in commands:
            with self.subTest(command=argv[0]):
                stderr = io.StringIO()
                with (
                    mock.patch(target, side_effect=error),
                    contextlib.redirect_stderr(stderr),
                ):
                    returncode = self.named_lane_main(argv)

                self.assertEqual(returncode, 2)
                self.assertEqual(
                    json.loads(stderr.getvalue()),
                    {"status": "blocked-safety", "reason": reason},
                )

    @retired_public_commands("materialize-worktree", "validate-worktree")
    def test_cli_classifies_bounded_failures_by_subcommand(self) -> None:
        cases = (
            ("deadline", lambda: ReviewTimeoutError("deadline"), 2),
            ("output-limit", lambda: ReviewOutputLimitError("limit"), 2),
            ("output-drain", lambda: ReviewOutputDrainError("drain"), 2),
            ("process-leak", lambda: ReviewProcessLeakError("leak"), 2),
            (
                "forwarded-signal",
                lambda: ForwardedSignal(signal.SIGTERM),
                128 + signal.SIGTERM,
            ),
        )
        commands = (
            (
                "materialize-worktree",
                "review_runtime.named_lane.materialize_worktree",
                (
                    "materialize-worktree",
                    "--source",
                    str(self.repo.resolve()),
                    "--worktree",
                    str(self.root / "classified-materialized-worktree"),
                    "--base",
                    "0" * 40,
                    "--head",
                    "0" * 40,
                ),
                "blocked-safety",
            ),
            (
                "validate-worktree",
                "review_runtime.named_lane.validate_worktree",
                (
                    "validate-worktree",
                    "--worktree",
                    str(self.repo.resolve()),
                    "--base",
                    "0" * 40,
                    "--head",
                    "0" * 40,
                ),
                "blocked-safety",
            ),
            (
                "legacy-short-prefix-receipts",
                "review_runtime.named_lane.legacy_short_prefix_receipts",
                (
                    "legacy-short-prefix-receipts",
                    "--source",
                    str(self.repo.resolve()),
                    "--temporary-path",
                    str(self.root / "classified-legacy-prefix-view"),
                    "--head",
                    "0" * 40,
                    "--phase",
                    "initial",
                ),
                "blocked-safety",
            ),
            (
                "run-claude",
                "review_runtime.named_lane.run_claude",
                (
                    "run-claude",
                    "--worktree",
                    str(self.repo.resolve()),
                    "--source-worktree",
                    str(self.source_control),
                    "--preflight-result",
                    str(self.root / "unused-classification-preflight.json"),
                    "--stdout-path",
                    str(self.root / "stdout"),
                    "--stderr-path",
                    str(self.root / "stderr"),
                    "--",
                    "/usr/bin/false",
                ),
                "inconclusive",
            ),
        )

        for command, target, argv, expected_status in commands:
            for reason, error_factory, expected_returncode in cases:
                with self.subTest(command=command, reason=reason):
                    stderr = io.StringIO()
                    with contextlib.ExitStack() as stack:
                        stack.enter_context(
                            mock.patch(target, side_effect=error_factory())
                        )
                        if command == "run-claude":
                            stack.enter_context(
                                mock.patch.object(
                                    named_lane_runtime,
                                    "_read_control_prompt",
                                    return_value=b"",
                                )
                            )
                        stack.enter_context(contextlib.redirect_stderr(stderr))
                        returncode = self.named_lane_main(argv)

                    self.assertEqual(returncode, expected_returncode)
                    self.assertEqual(
                        json.loads(stderr.getvalue()),
                        {"status": expected_status, "reason": reason},
                    )

    @retired_public_commands("materialize-worktree", "validate-worktree")
    def test_cli_wraps_thread_start_failure_by_subcommand(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        executable = self.make_executable("pass\n")
        commands = (
            (
                (
                    "materialize-worktree",
                    "--source",
                    str(self.repo.resolve()),
                    "--worktree",
                    str(self.root / "thread-start-materialized-worktree"),
                    "--base",
                    head,
                    "--head",
                    head,
                ),
                "blocked-safety",
            ),
            (
                (
                    "validate-worktree",
                    "--worktree",
                    str(self.repo.resolve()),
                    "--base",
                    head,
                    "--head",
                    head,
                ),
                "blocked-safety",
            ),
            (
                (
                    "legacy-short-prefix-receipts",
                    "--source",
                    str(self.repo.resolve()),
                    "--temporary-path",
                    str(self.root / "thread-start-legacy-prefix-view"),
                    "--head",
                    head,
                    "--phase",
                    "initial",
                ),
                "blocked-safety",
            ),
            (
                (
                    "run-claude",
                    "--worktree",
                    str(self.repo.resolve()),
                    "--source-worktree",
                    str(self.source_control),
                    "--preflight-result",
                    str(self.preflight_result_path(executable)),
                    "--stdout-path",
                    str(self.root / "thread-start.stdout"),
                    "--stderr-path",
                    str(self.root / "thread-start.stderr"),
                    "--",
                    str(executable),
                ),
                "inconclusive",
            ),
        )

        for argv, expected_status in commands:
            with self.subTest(command=argv[0]):
                stderr = io.StringIO()
                with contextlib.ExitStack() as stack:
                    stack.enter_context(
                        mock.patch(
                            "review_runtime.common.threading.Thread.start",
                            side_effect=RuntimeError("cannot start new thread"),
                        )
                    )
                    if argv[0] == "run-claude":
                        stack.enter_context(
                            mock.patch.object(
                                named_lane_runtime,
                                "_read_control_prompt",
                                return_value=b"",
                            )
                        )
                    stack.enter_context(contextlib.redirect_stderr(stderr))
                    returncode = self.named_lane_main(argv)

                self.assertEqual(returncode, 2)
                self.assertEqual(
                    json.loads(stderr.getvalue()),
                    {"status": expected_status, "reason": "output-drain"},
                )


if __name__ == "__main__":
    unittest.main()
