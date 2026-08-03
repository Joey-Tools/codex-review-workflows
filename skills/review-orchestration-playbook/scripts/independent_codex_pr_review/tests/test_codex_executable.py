from __future__ import annotations

import contextlib
import ctypes
import dis
import errno
import grp
import hashlib
import json
import os
import pathlib
import pwd
import signal
import stat
import subprocess
import sys
import time
import unittest
from collections.abc import Callable
from dataclasses import dataclass, replace
from types import SimpleNamespace
from unittest import mock

import review_supervisor.codex_executable as codex_executable
import review_supervisor.recovery_cleanup as recovery_cleanup

from review_supervisor.codex_executable import (
    AGGREGATE_SCHEMA_NAME,
    CODESIGN_PATH,
    CommandResult,
    CodexExecutableCustody,
    CodexExecutableCustodyStale,
    CodexExecutableError,
    CodexExecutableExecutionUnsupported,
    CodexExecutablePolicy,
    CodexExecutableRetentionRequired,
    ExecutableExclusionRoots,
    ExtendedMetadataEvidence,
    NodeIdentity,
    PreflightProcessClosureUnproven,
    ProcessQuiescenceEvidence,
    SNAPSHOT_DIRECTORY_PREFIX,
    SNAPSHOT_EXECUTABLE_MODE,
    SignatureMetadata,
    SnapshotCopyResult,
    SnapshotProtectionEvidence,
    SnapshotSeatbeltPolicy,
    _macos_acl_entries,
    _macos_acl_entry_count,
    _macos_fd_xattr_names,
    _validate_node,
    authenticate_codex_executable,
    build_snapshot_seatbelt_policy,
    copy_executable_from_fd,
    run_bounded_command,
    verify_macos_filesystem_metadata,
)
from review_supervisor.recovery_cleanup import (
    CustodiedManifest,
    QuarantinedRootRecoveryEvidence,
)
from tests.support import (
    _remove_exact_test_entry,
    _test_entry_object_identity,
    owned_temporary_directory,
)


SYNTHETIC_BINARY = b"synthetic codex executable\n"
SYNTHETIC_SCHEMA = b'{"title":"SyntheticAppServerV2"}\n'
TEAM_IDENTIFIER = "2DC432GLL2"
FULL_CDHASH = "a" * 64
VERSION = "codex-cli 0.145.0-alpha.18"
HELP = b"""Usage: codex app-server [OPTIONS]

Options:
      --stdio          Use the stdio transport
      --strict-config  Reject unknown configuration
"""
CLEAR_METADATA = ExtendedMetadataEvidence(0, (), False)
REQUIRE_LIVE_NO_CHILD_PROFILE_ENV = "CODEX_REVIEW_REQUIRE_LIVE_NO_CHILD_PROFILE"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class Fixture:
    source: pathlib.Path
    schema: pathlib.Path
    snapshot_parent: pathlib.Path
    roots: ExecutableExclusionRoots
    policy: CodexExecutablePolicy


class FakeRunner:
    def __init__(self, fixture: Fixture) -> None:
        self.fixture = fixture
        self.calls: list[tuple[tuple[str, ...], float, int]] = []
        self.executed_paths: list[pathlib.Path] = []
        self.version = VERSION.encode("ascii") + b"\n"
        self.version_stderr = b""
        self.help = HELP
        self.help_stderr = b""
        self.schema = SYNTHETIC_SCHEMA
        self.schema_stderr = b""
        self.source_verify_returncode = 0
        self.snapshot_verify_returncode = 0
        self.source_display_returncode = 0
        self.snapshot_display_returncode = 0
        self.source_metadata = self._valid_metadata()
        self.snapshot_metadata = self._valid_metadata()
        self.hook: Callable[[tuple[str, ...]], None] | None = None

    @staticmethod
    def _valid_metadata() -> bytes:
        return (
            b"Executable=/synthetic/Codex\n"
            + f"CandidateCDHashFull sha256={FULL_CDHASH}\n".encode("ascii")
            + f"TeamIdentifier={TEAM_IDENTIFIER}\n".encode("ascii")
        )

    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> CommandResult:
        self.calls.append((argv, timeout_seconds, max_output_bytes))
        if self.hook is not None:
            self.hook(argv)
        if argv[0] == CODESIGN_PATH:
            source_target = pathlib.Path(argv[-1]) == self.fixture.source
            if "--verify" in argv:
                return CommandResult(
                    argv,
                    (
                        self.source_verify_returncode
                        if source_target
                        else self.snapshot_verify_returncode
                    ),
                    b"",
                    b"valid on disk\nsatisfies its Designated Requirement\n",
                )
            if "--display" in argv:
                return CommandResult(
                    argv,
                    (
                        self.source_display_returncode
                        if source_target
                        else self.snapshot_display_returncode
                    ),
                    b"",
                    self.source_metadata if source_target else self.snapshot_metadata,
                )
        executable = pathlib.Path(argv[0])
        self.executed_paths.append(executable)
        if argv[1:] == ("--version",):
            return CommandResult(argv, 0, self.version, self.version_stderr)
        if argv[1:] == ("app-server", "--help"):
            return CommandResult(argv, 0, self.help, self.help_stderr)
        if argv[1:4] == (
            "app-server",
            "generate-json-schema",
            "--out",
        ):
            output = pathlib.Path(argv[4]) / AGGREGATE_SCHEMA_NAME
            output.write_bytes(self.schema)
            os.chmod(output, 0o600)
            return CommandResult(argv, 0, b"", self.schema_stderr)
        raise AssertionError(f"unexpected synthetic command: {argv!r}")


class FakeFilesystemMetadataVerifier:
    def __init__(
        self,
        callback: Callable[[int, pathlib.Path, str], ExtendedMetadataEvidence]
        | None = None,
    ) -> None:
        self.callback = callback
        self.calls: list[tuple[pathlib.Path, str]] = []

    def __call__(
        self,
        fd: int,
        path: pathlib.Path,
        kind: str,
    ) -> ExtendedMetadataEvidence:
        self.calls.append((path, kind))
        if self.callback is not None:
            return self.callback(fd, path, kind)
        return CLEAR_METADATA


class RecordingProtectionVerifier:
    def __init__(self) -> None:
        self.calls: list[tuple[SnapshotSeatbeltPolicy, SnapshotProtectionEvidence]] = []

    def __call__(
        self,
        policy: SnapshotSeatbeltPolicy,
        evidence: SnapshotProtectionEvidence,
    ) -> None:
        self.calls.append((policy, evidence))


class RecordingQuiescenceVerifier:
    def __init__(self) -> None:
        self.calls: list[ProcessQuiescenceEvidence] = []

    def __call__(self, evidence: ProcessQuiescenceEvidence) -> None:
        self.calls.append(evidence)


class FakeCFunction:
    def __init__(self, function: Callable[..., object]) -> None:
        self.function = function
        self.argtypes: object = None
        self.restype: object = None

    def __call__(self, *arguments: object) -> object:
        return self.function(*arguments)


class FakeAclLibc:
    def __init__(self, entry_count: int) -> None:
        remaining = entry_count

        def get_entry(*_arguments: object) -> int:
            nonlocal remaining
            if remaining:
                remaining -= 1
                return 0
            ctypes.set_errno(errno.EINVAL)
            return -1

        self.acl_get_fd_np = FakeCFunction(lambda *_arguments: 1)
        self.acl_get_entry = FakeCFunction(get_entry)
        self.acl_free = FakeCFunction(lambda *_arguments: 0)


class FakeAclTextLibc:
    def __init__(self, rendered: bytes) -> None:
        self.buffer = ctypes.create_string_buffer(rendered)

        def to_text(_acl: object, length: object) -> int:
            ctypes.cast(length, ctypes.POINTER(ctypes.c_ssize_t))[0] = len(rendered)
            return ctypes.addressof(self.buffer)

        self.acl_get_fd_np = FakeCFunction(lambda *_arguments: 1)
        self.acl_to_text = FakeCFunction(to_text)
        self.acl_free = FakeCFunction(lambda *_arguments: 0)


class FakeListXattrLibc:
    def __init__(self, responses: tuple[bytes, ...]) -> None:
        remaining = list(responses)

        def list_xattrs(
            _fd: object,
            buffer: object,
            size: object,
            _options: object,
        ) -> int:
            if not remaining:
                raise AssertionError("unexpected flistxattr call")
            payload = remaining.pop(0)
            if buffer is None:
                return len(payload)
            capacity = int(size)
            if len(payload) > capacity:
                ctypes.set_errno(errno.ERANGE)
                return -1
            ctypes.memmove(buffer, payload, len(payload))
            return len(payload)

        self.flistxattr = FakeCFunction(list_xattrs)


def _build_fixture(root: pathlib.Path) -> Fixture:
    application = root / "trusted-application"
    application.mkdir(mode=0o700)
    source = application / "codex"
    source.write_bytes(SYNTHETIC_BINARY)
    os.chmod(source, 0o700)

    schema = root / "aggregate-schema.json"
    schema.write_bytes(SYNTHETIC_SCHEMA)
    os.chmod(schema, 0o600)

    snapshot_parent = root / "supervisor-snapshots"
    snapshot_parent.mkdir(mode=0o700)
    os.chmod(snapshot_parent, 0o700)

    root_paths: dict[str, pathlib.Path] = {}
    for label in ("repo", "helper", "runtime", "retention", "checkout"):
        path = root / label
        path.mkdir(mode=0o700)
        root_paths[label] = path
    exclusions = ExecutableExclusionRoots(**root_paths)
    policy = CodexExecutablePolicy(
        expected_sha256=_sha256(SYNTHETIC_BINARY),
        expected_version=VERSION,
        expected_team_identifier=TEAM_IDENTIFIER,
        expected_full_cdhash=FULL_CDHASH,
        expected_schema_sha256=_sha256(SYNTHETIC_SCHEMA),
        max_executable_bytes=1024,
        max_schema_bytes=1024,
    )
    return Fixture(source, schema, snapshot_parent, exclusions, policy)


def _authenticate(
    fixture: Fixture,
    runner: FakeRunner,
    **overrides: object,
) -> CodexExecutableCustody:
    arguments: dict[str, object] = {
        "snapshot_parent": fixture.snapshot_parent,
        "exclusion_roots": fixture.roots,
        "aggregate_schema_path": fixture.schema,
        "command_runner": runner,
        "filesystem_metadata_verifier": FakeFilesystemMetadataVerifier(),
        "snapshot_protection_verifier": RecordingProtectionVerifier(),
        "quiescence_verifier": RecordingQuiescenceVerifier(),
        "policy": fixture.policy,
        "platform_name": "darwin",
    }
    arguments.update(overrides)
    return authenticate_codex_executable(fixture.source, **arguments)


def _protection(custody: CodexExecutableCustody) -> SnapshotProtectionEvidence:
    policy = custody.seatbelt_policy
    return SnapshotProtectionEvidence(
        snapshot_directory=policy.snapshot_directory,
        snapshot_policy_sha256=policy.sha256,
        effective_profile_sha256=_sha256(
            ("kernel-no-child-profile\n" + policy.rules).encode("ascii")
        ),
        kernel="macos-seatbelt",
        no_child_profile_verified=True,
        applied_before_snapshot_exec=True,
        denied_operations=policy.required_denials,
        self_mutation_probe_denied=True,
    )


def _quiescence(
    *,
    handoff_token: str | None = None,
    process_id: int | None = None,
    reason: str = "synthetic-supervisor-observed-quiescence",
    launch_state: str | None = None,
) -> ProcessQuiescenceEvidence:
    if launch_state is None:
        launch_state = (
            "bound-launch" if process_id is not None else "never-launched-abort"
        )
    return ProcessQuiescenceEvidence(
        handoff_token=handoff_token,
        process_id=process_id,
        leader_reaped=True,
        process_group_empty=True,
        descendant_handles_closed=True,
        observed_by_supervisor=True,
        reason=reason,
        launch_state=launch_state,
    )


def _cleanup(
    custody: CodexExecutableCustody,
    *,
    handoff_token: str | None = None,
    process_id: int | None = None,
) -> None:
    custody.confirm_process_quiescence(
        _quiescence(handoff_token=handoff_token, process_id=process_id)
    )
    custody.cleanup()


def _replace_snapshot_path(custody: CodexExecutableCustody) -> None:
    path = custody.snapshot_path
    path.unlink()
    path.write_bytes(SYNTHETIC_BINARY)
    os.chmod(path, SNAPSHOT_EXECUTABLE_MODE)


def _published_launch(
    launched: object,
    stdout_fd: int,
    stderr_fd: int,
) -> Callable[..., tuple[object, int, int]]:
    def launch(
        _prepared: object,
        _argv: tuple[str, ...],
        *,
        ownership: codex_executable._PreflightLaunchOwnership,
    ) -> tuple[object, int, int]:
        ownership.track_descriptors(stdout_fd, stderr_fd)
        ownership.arm_launch()
        ownership.publish_launched(launched)
        receipt = (launched, stdout_fd, stderr_fd)
        ownership.publish_receipt(receipt)
        return receipt

    return launch


def _call_result_store_offset(
    function: Callable[..., object],
    *,
    called_name: str,
    stored_name: str,
) -> int:
    instructions = tuple(dis.get_instructions(function))
    for index, instruction in enumerate(instructions):
        if not instruction.opname.startswith("CALL"):
            continue
        prior = instructions[max(0, index - 64) : index]
        if not any(candidate.argval == called_name for candidate in prior):
            continue
        following = instructions[index + 1]
        if (
            following.opname in {"STORE_FAST", "STORE_DEREF"}
            and following.argval == stored_name
        ):
            return following.offset
    raise AssertionError(
        f"missing {called_name} CALL-to-{stored_name} local-store boundary"
    )


def _call_result_next_opcode_offset(
    function: Callable[..., object],
    *,
    called_name: str,
) -> int:
    instructions = tuple(dis.get_instructions(function))
    for index, instruction in enumerate(instructions):
        if not instruction.opname.startswith("CALL"):
            continue
        prior = instructions[max(0, index - 64) : index]
        following = instructions[index + 1]
        if (
            any(candidate.argval == called_name for candidate in prior)
            and following.opname == "POP_TOP"
        ):
            return following.offset
    raise AssertionError(f"missing {called_name} CALL result boundary")


def _call_opcode_offset(
    function: Callable[..., object],
    *,
    called_name: str,
) -> int:
    instructions = tuple(dis.get_instructions(function))
    for index, instruction in enumerate(instructions):
        if not instruction.opname.startswith("CALL"):
            continue
        prior = instructions[max(0, index - 64) : index]
        if any(candidate.argval == called_name for candidate in prior):
            return instruction.offset
    raise AssertionError(f"missing {called_name} CALL boundary")


def _call_result_offset_with_argument(
    function: Callable[..., object],
    *,
    called_name: str,
    argument_name: str,
    following_opname: str,
    following_argval: str | None = None,
) -> int:
    instructions = tuple(dis.get_instructions(function))
    for index, instruction in enumerate(instructions):
        if not instruction.opname.startswith("CALL"):
            continue
        prior = instructions[max(0, index - 64) : index]
        following = instructions[index + 1]
        if (
            any(candidate.argval == called_name for candidate in prior)
            and any(candidate.argval == argument_name for candidate in prior[-16:])
            and following.opname == following_opname
            and (following_argval is None or following.argval == following_argval)
        ):
            return following.offset
    raise AssertionError(f"missing {called_name}({argument_name}) CALL result boundary")


def _instruction_after_offset(function: Callable[..., object], offset: int) -> int:
    instructions = tuple(dis.get_instructions(function))
    for index, instruction in enumerate(instructions[:-1]):
        if instruction.offset == offset:
            return instructions[index + 1].offset
    raise AssertionError(f"missing instruction after offset {offset}")


class CodexExecutableAuthenticationTests(unittest.TestCase):
    def test_bounded_preflight_reports_explicit_unproven_closure(self) -> None:
        stdout_read, stdout_write = os.pipe()
        stderr_read, stderr_write = os.pipe()
        os.close(stdout_write)
        os.close(stderr_write)
        launched = SimpleNamespace(
            pid=424242,
            pgid=424242,
            session_id=424242,
            start_identity="synthetic-start",
            profile_sha256="a" * 64,
        )
        with (
            mock.patch.object(
                codex_executable,
                "_prepare_root_protected_no_child_profile",
                return_value=object(),
            ),
            mock.patch.object(
                codex_executable,
                "_launch_prepared_bounded_command",
                side_effect=_published_launch(
                    launched,
                    stdout_read,
                    stderr_read,
                ),
            ),
            mock.patch.object(
                codex_executable,
                "wait_terminal",
                side_effect=TimeoutError("synthetic wait failure"),
            ),
            mock.patch.object(
                codex_executable,
                "_terminate_and_reap_preflight",
                side_effect=TimeoutError("synthetic cleanup failure"),
            ),
            self.assertRaises(PreflightProcessClosureUnproven) as caught,
        ):
            run_bounded_command(
                ("/usr/bin/true",),
                timeout_seconds=1.0,
                max_output_bytes=1024,
            )

        evidence = caught.exception.evidence
        self.assertEqual(evidence.leader_pid, launched.pid)
        self.assertFalse(evidence.leader_reaped)
        self.assertFalse(evidence.permitted_process_closure_proven)
        self.assertFalse(evidence.process_group_emptiness_used_as_descendant_proof)

    def test_selector_creation_failure_terminates_reaps_and_closes_streams(
        self,
    ) -> None:
        stdout_read, stdout_write = os.pipe()
        stderr_read, stderr_write = os.pipe()
        os.close(stdout_write)
        os.close(stderr_write)
        launched = SimpleNamespace(
            pid=424242,
            pgid=424242,
            session_id=424242,
            start_identity="synthetic-start",
            profile_sha256="a" * 64,
        )
        with (
            mock.patch.object(
                codex_executable,
                "_prepare_root_protected_no_child_profile",
                return_value=object(),
            ),
            mock.patch.object(
                codex_executable,
                "_launch_prepared_bounded_command",
                side_effect=_published_launch(
                    launched,
                    stdout_read,
                    stderr_read,
                ),
            ),
            mock.patch.object(
                codex_executable.selectors,
                "DefaultSelector",
                side_effect=RuntimeError("synthetic selector creation failure"),
            ),
            mock.patch.object(
                codex_executable,
                "_terminate_and_reap_preflight",
                return_value=-signal.SIGKILL,
            ) as terminate,
            self.assertRaisesRegex(
                RuntimeError,
                "synthetic selector creation failure",
            ),
        ):
            run_bounded_command(
                ("/usr/bin/true",),
                timeout_seconds=1.0,
                max_output_bytes=1024,
            )

        terminate.assert_called_once()
        self.assertIs(terminate.call_args.args[0], launched)
        for descriptor in (stdout_read, stderr_read):
            with self.subTest(descriptor=descriptor):
                with self.assertRaises(OSError) as raised:
                    os.fstat(descriptor)
                self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_launch_receipt_setup_interrupt_terminates_and_reaps(self) -> None:
        stdout_read, stdout_write = os.pipe()
        stderr_read, stderr_write = os.pipe()
        os.close(stdout_write)
        os.close(stderr_write)
        launched = SimpleNamespace(
            pid=424242,
            pgid=424242,
            session_id=424242,
            start_identity="synthetic-start",
            profile_sha256="a" * 64,
        )
        with (
            mock.patch.object(
                codex_executable,
                "_prepare_root_protected_no_child_profile",
                return_value=object(),
            ),
            mock.patch.object(
                codex_executable,
                "_launch_prepared_bounded_command",
                side_effect=_published_launch(
                    launched,
                    stdout_read,
                    stderr_read,
                ),
            ),
            mock.patch.object(
                codex_executable.time,
                "monotonic",
                side_effect=(
                    KeyboardInterrupt("synthetic receipt setup interrupt"),
                    100.0,
                ),
            ),
            mock.patch.object(
                codex_executable,
                "_terminate_and_reap_preflight",
                return_value=-signal.SIGKILL,
            ) as terminate,
            self.assertRaisesRegex(
                KeyboardInterrupt,
                "synthetic receipt setup interrupt",
            ),
        ):
            run_bounded_command(
                ("/usr/bin/true",),
                timeout_seconds=1.0,
                max_output_bytes=1024,
            )

        terminate.assert_called_once()
        self.assertIs(terminate.call_args.args[0], launched)
        for descriptor in (stdout_read, stderr_read):
            with self.assertRaises(OSError) as raised:
                os.fstat(descriptor)
            self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_no_child_launch_call_to_store_interrupt_terminates_published_leader(
        self,
    ) -> None:
        from review_supervisor import no_child_profile

        prepared = object()
        ownership = codex_executable._PreflightLaunchOwnership(prepared)

        def launch_template(
            _prepared: object,
            _argv: tuple[str, ...],
            *,
            cwd: str,
            environment: dict[str, str],
            stdin_fd: int,
            stdout_fd: int,
            stderr_fd: int,
            result_owner: object,
        ) -> object:
            del (
                _prepared,
                _argv,
                cwd,
                environment,
                stdin_fd,
                stdout_fd,
                stderr_fd,
            )
            launched = SimpleNamespace(
                pid=424242,
                pgid=424242,
                session_id=424242,
                start_identity="synthetic-start",
                profile_sha256="a" * 64,
            )
            result_owner.publish(launched)
            return launched

        target_offset = _call_result_store_offset(
            codex_executable._launch_prepared_bounded_command,
            called_name="_launch_no_child_process_with_ownership",
            stored_name="launched",
        )
        interruption = KeyboardInterrupt(
            "injected no-child launch CALL-to-STORE interrupt"
        )
        injected = False

        def interrupt_result_store(
            frame: object,
            event: str,
            _argument: object,
        ) -> object:
            nonlocal injected
            if (
                getattr(frame, "f_code", None)
                is codex_executable._launch_prepared_bounded_command.__code__
            ):
                setattr(frame, "f_trace_opcodes", True)
                if (
                    not injected
                    and event == "opcode"
                    and getattr(frame, "f_lasti", None) == target_offset
                ):
                    injected = True
                    raise interruption
            return interrupt_result_store

        previous_trace = sys.gettrace()
        try:
            with (
                mock.patch.object(
                    no_child_profile,
                    "PreparedNoChildProfile",
                    object,
                ),
                mock.patch.object(
                    no_child_profile,
                    "launch_prepared_no_child_process",
                    launch_template,
                ),
                mock.patch.object(
                    codex_executable,
                    "_terminate_and_reap_preflight",
                    return_value=-signal.SIGKILL,
                ) as terminate,
            ):
                sys.settrace(interrupt_result_store)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    codex_executable._launch_prepared_bounded_command(
                        prepared,
                        ("/usr/bin/true",),
                        ownership=ownership,
                    )
        finally:
            sys.settrace(previous_trace)

        self.assertTrue(injected)
        self.assertIs(caught.exception, interruption)
        terminate.assert_called_once()
        self.assertEqual(terminate.call_args.args[0].pid, 424242)
        self.assertTrue(ownership.closure_proven)
        self.assertEqual(ownership.state, "closed")
        self.assertEqual(ownership.descriptors, set())

    def test_preflight_close_result_interrupt_abandons_reused_descriptor(
        self,
    ) -> None:
        ownership = codex_executable._PreflightLaunchOwnership(object())
        descriptor, peer = os.pipe()
        ownership.track_descriptors(descriptor)
        real_close = os.close
        interruption = KeyboardInterrupt(
            "injected preflight descriptor close result interrupt"
        )
        reused_descriptor: int | None = None

        def close_then_reuse(candidate: int) -> None:
            nonlocal reused_descriptor
            self.assertEqual(candidate, descriptor)
            real_close(candidate)
            replacement = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
            if replacement != candidate:
                os.dup2(replacement, candidate, inheritable=False)
                real_close(replacement)
                replacement = candidate
            reused_descriptor = replacement
            raise interruption

        try:
            with mock.patch.object(
                codex_executable.os,
                "close",
                side_effect=close_then_reuse,
            ) as first_close:
                failures = codex_executable._close_preflight_launch_descriptors(
                    ownership
                )

            self.assertEqual(failures, (interruption,))
            first_close.assert_called_once_with(descriptor)
            self.assertEqual(reused_descriptor, descriptor)
            self.assertEqual(
                ownership.descriptor_close_outcomes[descriptor],
                "close-outcome-unproven",
            )
            self.assertIs(
                ownership.descriptor_close_errors[descriptor],
                interruption,
            )

            with mock.patch.object(
                codex_executable.os,
                "close",
                wraps=real_close,
            ) as retry_close:
                with self.assertRaises(KeyboardInterrupt) as caught:
                    ownership.close_descriptors_for_recovery()
            self.assertIs(caught.exception, interruption)
            retry_close.assert_not_called()
            os.fstat(descriptor)
        finally:
            if reused_descriptor is not None:
                real_close(reused_descriptor)
            else:
                try:
                    real_close(descriptor)
                except OSError as error:
                    if error.errno != errno.EBADF:
                        raise
            real_close(peer)

    def test_no_child_publication_result_interrupt_does_not_repeat_owner_callback(
        self,
    ) -> None:
        launched = object()

        class ExternalOwner:
            def __init__(self) -> None:
                self.launched: object | None = None
                self.publish_calls = 0

            def publish(self, candidate: object) -> None:
                self.publish_calls += 1
                if self.launched is not None and self.launched is not candidate:
                    raise ValueError("external owner was rebound")
                self.launched = candidate

            def owns(self, candidate: object) -> bool:
                return self.launched is candidate

        external_owner = ExternalOwner()
        publication_owner = codex_executable._NoChildLaunchResultOwner(
            external_owner=external_owner
        )
        target_offset = _call_result_next_opcode_offset(
            codex_executable._NoChildLaunchResultOwner.finish_publication,
            called_name="publish",
        )
        interruption = KeyboardInterrupt(
            "injected external-owner publication result interrupt"
        )
        injected = False

        def interrupt_publication_result(
            frame: object,
            event: str,
            _argument: object,
        ) -> object:
            nonlocal injected
            if (
                getattr(frame, "f_code", None)
                is codex_executable._NoChildLaunchResultOwner.finish_publication.__code__
            ):
                setattr(frame, "f_trace_opcodes", True)
                if (
                    not injected
                    and event == "opcode"
                    and getattr(frame, "f_lasti", None) == target_offset
                ):
                    injected = True
                    raise interruption
            return interrupt_publication_result

        previous_trace = sys.gettrace()
        try:
            sys.settrace(interrupt_publication_result)
            with self.assertRaises(KeyboardInterrupt) as caught:
                publication_owner.publish(launched)
        finally:
            sys.settrace(previous_trace)

        self.assertTrue(injected)
        self.assertIs(caught.exception, interruption)
        self.assertEqual(external_owner.publish_calls, 1)
        self.assertTrue(publication_owner.publication_complete)
        self.assertTrue(publication_owner.owns(launched))
        publication_owner.finish_publication()
        self.assertEqual(external_owner.publish_calls, 1)

    def test_preflight_owner_recovers_partial_launched_publication(
        self,
    ) -> None:
        ownership = codex_executable._PreflightLaunchOwnership(object())
        ownership.arm_launch()
        launched = object()
        instructions = tuple(
            dis.get_instructions(
                codex_executable._PreflightLaunchOwnership.publish_launched
            )
        )
        store_index = next(
            index
            for index, instruction in enumerate(instructions[:-1])
            if instruction.opname == "STORE_ATTR" and instruction.argval == "launched"
        )
        target_offset = instructions[store_index + 1].offset
        interruption = KeyboardInterrupt(
            "injected partial preflight owner publication interrupt"
        )
        injected = False

        def interrupt_after_launched_store(
            frame: object,
            event: str,
            _argument: object,
        ) -> object:
            nonlocal injected
            if (
                getattr(frame, "f_code", None)
                is codex_executable._PreflightLaunchOwnership.publish_launched.__code__
            ):
                setattr(frame, "f_trace_opcodes", True)
                if (
                    not injected
                    and event == "opcode"
                    and getattr(frame, "f_lasti", None) == target_offset
                ):
                    injected = True
                    raise interruption
            return interrupt_after_launched_store

        previous_trace = sys.gettrace()
        try:
            sys.settrace(interrupt_after_launched_store)
            with self.assertRaises(KeyboardInterrupt) as caught:
                ownership.publish(launched)
        finally:
            sys.settrace(previous_trace)

        self.assertTrue(injected)
        self.assertIs(caught.exception, interruption)
        self.assertIs(ownership.launched, launched)
        self.assertEqual(ownership.state, "launch-may-have-started")
        self.assertFalse(ownership.owns(launched))
        ownership.publish(launched)
        self.assertTrue(ownership.owns(launched))
        self.assertEqual(ownership.state, "leader-bound")

    def test_bounded_command_call_to_store_interrupt_recovers_published_receipt(
        self,
    ) -> None:
        stdout_read, stdout_write = os.pipe()
        stderr_read, stderr_write = os.pipe()
        os.close(stdout_write)
        os.close(stderr_write)
        launched = SimpleNamespace(
            pid=424242,
            pgid=424242,
            session_id=424242,
            start_identity="synthetic-start",
            profile_sha256="a" * 64,
        )
        target_offset = _call_result_store_offset(
            run_bounded_command,
            called_name="_launch_prepared_bounded_command",
            stored_name="launch_receipt",
        )
        interruption = KeyboardInterrupt(
            "injected bounded command CALL-to-STORE interrupt"
        )
        injected = False
        ownerships: list[codex_executable._PreflightLaunchOwnership] = []

        def publish_receipt(
            _prepared: object,
            _argv: tuple[str, ...],
            *,
            ownership: codex_executable._PreflightLaunchOwnership,
        ) -> tuple[object, int, int]:
            ownerships.append(ownership)
            return _published_launch(
                launched,
                stdout_read,
                stderr_read,
            )(
                _prepared,
                _argv,
                ownership=ownership,
            )

        def interrupt_result_store(
            frame: object,
            event: str,
            _argument: object,
        ) -> object:
            nonlocal injected
            if getattr(frame, "f_code", None) is run_bounded_command.__code__:
                setattr(frame, "f_trace_opcodes", True)
                if (
                    not injected
                    and event == "opcode"
                    and getattr(frame, "f_lasti", None) == target_offset
                ):
                    injected = True
                    raise interruption
            return interrupt_result_store

        previous_trace = sys.gettrace()
        try:
            with (
                mock.patch.object(
                    codex_executable,
                    "_prepare_root_protected_no_child_profile",
                    return_value=object(),
                ),
                mock.patch.object(
                    codex_executable,
                    "_launch_prepared_bounded_command",
                    side_effect=publish_receipt,
                ),
                mock.patch.object(
                    codex_executable,
                    "_terminate_and_reap_preflight",
                    return_value=-signal.SIGKILL,
                ) as terminate,
            ):
                sys.settrace(interrupt_result_store)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    run_bounded_command(
                        ("/usr/bin/true",),
                        timeout_seconds=1.0,
                        max_output_bytes=1024,
                    )
        finally:
            sys.settrace(previous_trace)

        self.assertIs(caught.exception, interruption)
        self.assertTrue(injected)
        terminate.assert_called_once_with(
            launched,
            deadline=mock.ANY,
        )
        self.assertEqual(len(ownerships), 1)
        self.assertTrue(ownerships[0].closure_proven)
        self.assertEqual(ownerships[0].state, "closed")
        for descriptor in (stdout_read, stderr_read):
            with self.assertRaises(OSError) as raised:
                os.fstat(descriptor)
            self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_cleanup_keyboard_interrupt_becomes_typed_retention(
        self,
    ) -> None:
        stdout_read, stdout_write = os.pipe()
        stderr_read, stderr_write = os.pipe()
        os.close(stdout_write)
        os.close(stderr_write)
        launched = SimpleNamespace(
            pid=424242,
            pgid=424242,
            session_id=424242,
            start_identity="synthetic-start",
            profile_sha256="a" * 64,
        )
        cleanup_interrupt = KeyboardInterrupt("injected terminate and reap interrupt")
        with (
            mock.patch.object(
                codex_executable,
                "_prepare_root_protected_no_child_profile",
                return_value=object(),
            ),
            mock.patch.object(
                codex_executable,
                "_launch_prepared_bounded_command",
                side_effect=_published_launch(
                    launched,
                    stdout_read,
                    stderr_read,
                ),
            ),
            mock.patch.object(
                codex_executable,
                "wait_terminal",
                side_effect=RuntimeError("injected command failure"),
            ),
            mock.patch.object(
                codex_executable,
                "_terminate_and_reap_preflight",
                side_effect=cleanup_interrupt,
            ) as terminate,
            self.assertRaises(PreflightProcessClosureUnproven) as caught,
        ):
            run_bounded_command(
                ("/usr/bin/true",),
                timeout_seconds=1.0,
                max_output_bytes=1024,
            )

        terminate.assert_called_once()
        self.assertIs(caught.exception.__cause__, cleanup_interrupt)
        self.assertEqual(caught.exception.evidence.leader_pid, 424242)
        self.assertFalse(caught.exception.evidence.permitted_process_closure_proven)
        ownership = next(
            resource
            for resource in caught.exception.retained_resources
            if isinstance(
                resource,
                codex_executable._PreflightLaunchOwnership,
            )
        )
        self.assertIs(ownership.launched, launched)
        self.assertEqual(ownership.state, "retained")
        self.assertEqual(
            ownership.descriptors,
            {stdout_read, stderr_read},
        )
        try:
            os.fstat(stdout_read)
            os.fstat(stderr_read)
        finally:
            ownership.close_descriptors_for_recovery()

    def test_selector_registration_failure_terminates_reaps_and_closes_streams(
        self,
    ) -> None:
        stdout_read, stdout_write = os.pipe()
        stderr_read, stderr_write = os.pipe()
        os.close(stdout_write)
        os.close(stderr_write)
        launched = SimpleNamespace(
            pid=424242,
            pgid=424242,
            session_id=424242,
            start_identity="synthetic-start",
            profile_sha256="a" * 64,
        )

        class FailingSelector:
            def __init__(self) -> None:
                self.registrations = 0
                self.closed = False

            def register(self, descriptor: int, _events: int) -> None:
                del descriptor
                self.registrations += 1
                if self.registrations == 2:
                    raise RuntimeError("synthetic selector registration failure")

            def get_map(self) -> dict[int, object]:
                return {stdout_read: object()}

            def close(self) -> None:
                self.closed = True

        selector = FailingSelector()
        with (
            mock.patch.object(
                codex_executable,
                "_prepare_root_protected_no_child_profile",
                return_value=object(),
            ),
            mock.patch.object(
                codex_executable,
                "_launch_prepared_bounded_command",
                side_effect=_published_launch(
                    launched,
                    stdout_read,
                    stderr_read,
                ),
            ),
            mock.patch.object(
                codex_executable.selectors,
                "DefaultSelector",
                return_value=selector,
            ),
            mock.patch.object(
                codex_executable,
                "_terminate_and_reap_preflight",
                return_value=-signal.SIGKILL,
            ) as terminate,
            self.assertRaisesRegex(
                RuntimeError,
                "synthetic selector registration failure",
            ),
        ):
            run_bounded_command(
                ("/usr/bin/true",),
                timeout_seconds=1.0,
                max_output_bytes=1024,
            )

        terminate.assert_called_once()
        self.assertIs(terminate.call_args.args[0], launched)
        self.assertEqual(selector.registrations, 2)
        self.assertTrue(selector.closed)
        for descriptor in (stdout_read, stderr_read):
            with self.subTest(descriptor=descriptor):
                with self.assertRaises(OSError) as raised:
                    os.fstat(descriptor)
                self.assertEqual(raised.exception.errno, errno.EBADF)

    @unittest.skipUnless(
        os.environ.get(REQUIRE_LIVE_NO_CHILD_PROFILE_ENV) == "1",
        "live no-child profile regression requires an explicit opt-in",
    )
    def test_bounded_preflight_cannot_leave_child_after_closing_stdio(
        self,
    ) -> None:
        nonce = f"codex-preflight-escape-{os.getpid()}-{time.time_ns()}"
        script = (
            "exec 1>&- 2>&-; "
            '/bin/sh -c \'trap "" TERM; while :; do :; done\' "$1" & '
            "child=$!; "
            '[ -n "$child" ] && kill -0 "$child" 2>/dev/null'
        )
        result = run_bounded_command(
            ("/bin/sh", "-c", script, "bounded-preflight", nonce),
            timeout_seconds=5.0,
            max_output_bytes=4096,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNotNone(result.process_closure)
        assert result.process_closure is not None
        self.assertTrue(result.process_closure.leader_reaped)
        self.assertTrue(result.process_closure.permitted_process_closure_proven)
        self.assertFalse(
            result.process_closure.process_group_emptiness_used_as_descendant_proof
        )

        process_table = subprocess.run(
            ("/bin/ps", "-axo", "pid=,command="),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5.0,
        )
        self.assertEqual(process_table.returncode, 0, process_table.stderr)
        self.assertLessEqual(len(process_table.stdout), 4 * 1024 * 1024)
        residual = [
            line
            for line in process_table.stdout.splitlines()
            if nonce.encode("ascii") in line
        ]
        for line in residual:
            try:
                os.kill(int(line.split(None, 1)[0]), signal.SIGKILL)
            except (ProcessLookupError, ValueError):
                pass
        self.assertEqual(residual, [])

    def test_macos_acl_enumerator_counts_successful_zero_returns(self) -> None:
        for expected in (0, 2):
            with self.subTest(expected=expected):
                with (
                    mock.patch(
                        "review_supervisor.codex_executable.ctypes.CDLL",
                        return_value=FakeAclLibc(expected),
                    ),
                    mock.patch(
                        "review_supervisor.codex_executable.sys.platform",
                        "darwin",
                    ),
                ):
                    self.assertEqual(_macos_acl_entry_count(123), expected)

    def test_macos_acl_serializer_requires_bounded_exact_entries(self) -> None:
        entry = b"group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:deny:delete"
        cases = (
            (b"!#acl 1\n" + entry + b"\n", (entry.decode("ascii"),), None),
            (b"!#acl 2\n" + entry + b"\n", None, "malformed"),
            (b"!#acl 1\n" + entry, None, "malformed"),
            (b"not-an-acl\n", None, "header"),
        )
        for rendered, expected, error in cases:
            with self.subTest(error=error):
                with (
                    mock.patch(
                        "review_supervisor.codex_executable.ctypes.CDLL",
                        return_value=FakeAclTextLibc(rendered),
                    ),
                    mock.patch(
                        "review_supervisor.codex_executable.sys.platform",
                        "darwin",
                    ),
                ):
                    if error is None:
                        self.assertEqual(_macos_acl_entries(123), expected)
                    else:
                        with self.assertRaisesRegex(ValueError, error):
                            _macos_acl_entries(123)

    def test_macos_xattr_enumerator_requires_a_stable_bounded_name_list(
        self,
    ) -> None:
        stable = b"user.z\0com.apple.test\0"
        cases = (
            (
                (stable, stable, stable, stable),
                ("com.apple.test", "user.z"),
                None,
            ),
            ((b"", b""), None, None),
            ((b"duplicate\0duplicate\0",) * 4, None, "duplicates"),
            ((b"not-terminated",) * 4, None, "malformed"),
            ((b"\xff\0",) * 4, None, "not UTF-8"),
            ((b"a\0", b"a\0", b"b\0", b"a\0"), None, "changed"),
            ((b"x" * 4097,), None, "byte bound"),
        )
        for responses, expected, error in cases:
            with self.subTest(error=error, response_count=len(responses)):
                with (
                    mock.patch(
                        "review_supervisor.codex_executable.ctypes.CDLL",
                        return_value=FakeListXattrLibc(responses),
                    ),
                    mock.patch(
                        "review_supervisor.codex_executable.sys.platform",
                        "darwin",
                    ),
                ):
                    if error is None:
                        self.assertEqual(_macos_fd_xattr_names(123), expected or ())
                    else:
                        with self.assertRaisesRegex((OSError, ValueError), error):
                            _macos_fd_xattr_names(123)

    def test_macos_metadata_allows_only_exact_signed_bundle_xattrs(self) -> None:
        cases = (
            (
                pathlib.Path("/Applications/ChatGPT.app"),
                "directory",
                (
                    "com.apple.macl",
                    "com.apple.metadata:_kMDItemLastOutOfSpotlightEngagementDate",
                    "com.apple.provenance",
                ),
                True,
            ),
            (
                pathlib.Path("/Applications/ChatGPT.app/Contents/Resources/codex"),
                "file",
                ("com.apple.provenance",),
                True,
            ),
            (
                pathlib.Path("/Applications/Other.app"),
                "directory",
                ("com.apple.provenance",),
                True,
            ),
            (
                pathlib.Path("/usr"),
                "directory",
                ("com.apple.rootless",),
                True,
            ),
            (
                pathlib.Path("/Applications/Other.app"),
                "directory",
                ("com.apple.rootless",),
                False,
            ),
            (
                pathlib.Path("/Applications/Other.app"),
                "directory",
                ("user.synthetic",),
                False,
            ),
            (
                pathlib.Path("/Applications/ChatGPT.app/Contents"),
                "directory",
                ("com.apple.quarantine",),
                False,
            ),
        )
        for path, kind, names, accepted in cases:
            with self.subTest(path=path, names=names):
                with (
                    mock.patch(
                        "review_supervisor.codex_executable._macos_fd_xattr_names",
                        return_value=names,
                    ),
                    mock.patch(
                        "review_supervisor.codex_executable._macos_acl_entries",
                        return_value=(),
                    ),
                    mock.patch(
                        "review_supervisor.codex_executable.os.fstat",
                        return_value=os.stat("/"),
                    ),
                ):
                    if accepted:
                        evidence = verify_macos_filesystem_metadata(123, path, kind)
                        self.assertEqual(evidence.xattrs, names)
                    else:
                        with self.assertRaisesRegex(ValueError, "xattrs"):
                            verify_macos_filesystem_metadata(123, path, kind)

    def test_macos_metadata_accepts_only_the_restrictive_home_acl(self) -> None:
        home = pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir)
        restrictive = (
            "group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:deny:delete"
        )
        for path, entries, accepted in (
            (home, (restrictive,), True),
            (home / "child", (restrictive,), False),
            (home, ("group:unsafe:allow:write",), False),
        ):
            with self.subTest(path=path, entries=entries):
                with (
                    mock.patch(
                        "review_supervisor.codex_executable._macos_fd_xattr_names",
                        return_value=(),
                    ),
                    mock.patch(
                        "review_supervisor.codex_executable._macos_acl_entries",
                        return_value=entries,
                    ),
                    mock.patch(
                        "review_supervisor.codex_executable.os.fstat",
                        return_value=os.stat("/"),
                    ),
                ):
                    if accepted:
                        evidence = verify_macos_filesystem_metadata(
                            123, path, "directory"
                        )
                        self.assertEqual(evidence.acl_entries, entries)
                    else:
                        with self.assertRaisesRegex(ValueError, "ACLs"):
                            verify_macos_filesystem_metadata(123, path, "directory")

    def test_macos_metadata_rechecks_the_combined_acl_and_xattr_snapshot(
        self,
    ) -> None:
        unsafe_acl = ("group:unsafe:allow:write",)
        cases = (
            (((), ("user.synthetic",)), ((), ())),
            (((), ()), ((), unsafe_acl)),
        )
        for xattrs, acls in cases:
            with (
                self.subTest(xattrs=xattrs, acls=acls),
                mock.patch(
                    "review_supervisor.codex_executable._macos_fd_xattr_names",
                    side_effect=xattrs,
                ),
                mock.patch(
                    "review_supervisor.codex_executable._macos_acl_entries",
                    side_effect=acls,
                ),
                mock.patch(
                    "review_supervisor.codex_executable.os.fstat",
                    return_value=os.stat("/"),
                ),
                self.assertRaisesRegex(OSError, "changed during inspection"),
            ):
                verify_macos_filesystem_metadata(
                    123,
                    pathlib.Path("/synthetic"),
                    "directory",
                )

    def test_relaxed_directory_metadata_inspection_uses_property_scoped_identity(
        self,
    ) -> None:
        directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, directory_fd)
        base = NodeIdentity.from_stat(os.stat("/"))
        churned = replace(
            base,
            link_count=base.link_count + 1,
            size=base.size + 1,
            mtime_ns=base.mtime_ns + 1,
            ctime_ns=base.ctime_ns + 1,
        )
        access_policy_changed = replace(churned, mode=churned.mode ^ stat.S_IWUSR)

        for identities, accepted in (
            ((base, churned, churned), True),
            ((base, access_policy_changed, access_policy_changed), False),
        ):
            with (
                self.subTest(accepted=accepted),
                mock.patch.object(
                    NodeIdentity,
                    "from_stat",
                    side_effect=identities,
                ),
                mock.patch(
                    "review_supervisor.codex_executable."
                    "_read_macos_filesystem_metadata",
                    return_value=CLEAR_METADATA,
                ),
            ):
                if accepted:
                    evidence = codex_executable.inspect_macos_filesystem_metadata(
                        directory_fd,
                        "directory",
                        require_directory_metadata_stability=False,
                    )
                    self.assertEqual(evidence, CLEAR_METADATA)
                else:
                    with self.assertRaisesRegex(OSError, "changed during inspection"):
                        codex_executable.inspect_macos_filesystem_metadata(
                            directory_fd,
                            "directory",
                            require_directory_metadata_stability=False,
                        )

    def test_directory_metadata_inspection_ignores_pure_ctime_churn(
        self,
    ) -> None:
        directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, directory_fd)
        base = NodeIdentity.from_stat(os.stat("/"))
        churned = replace(base, ctime_ns=base.ctime_ns + 1)
        with (
            mock.patch.object(
                NodeIdentity,
                "from_stat",
                side_effect=(base, churned, churned),
            ),
            mock.patch(
                "review_supervisor.codex_executable._read_macos_filesystem_metadata",
                return_value=CLEAR_METADATA,
            ),
        ):
            evidence = codex_executable.inspect_macos_filesystem_metadata(
                directory_fd,
                "directory",
            )
        self.assertEqual(evidence, CLEAR_METADATA)

    def test_transient_restored_directory_mode_is_not_inferred_from_ctime(
        self,
    ) -> None:
        with owned_temporary_directory("codex-metadata-race-") as root:
            fixture = _build_fixture(root)
            mutated = False

            def inspect(
                fd: int,
                path: pathlib.Path,
                _kind: str,
            ) -> ExtendedMetadataEvidence:
                nonlocal mutated
                if path == fixture.source.parent and not mutated:
                    before = os.fstat(fd).st_ctime_ns
                    os.fchmod(fd, 0o710)
                    os.fchmod(fd, 0o700)
                    self.assertNotEqual(before, os.fstat(fd).st_ctime_ns)
                    mutated = True
                return CLEAR_METADATA

            custody = _authenticate(
                fixture,
                FakeRunner(fixture),
                filesystem_metadata_verifier=FakeFilesystemMetadataVerifier(inspect),
            )
            _cleanup(custody)
            self.assertTrue(mutated)

    def test_directory_access_policy_change_is_rejected_directly(self) -> None:
        with owned_temporary_directory("codex-metadata-policy-") as root:
            fixture = _build_fixture(root)
            changed = False

            def inspect(
                fd: int,
                path: pathlib.Path,
                _kind: str,
            ) -> ExtendedMetadataEvidence:
                nonlocal changed
                if path == fixture.source.parent and not changed:
                    os.fchmod(fd, 0o500)
                    changed = True
                return CLEAR_METADATA

            try:
                with self.assertRaisesRegex(
                    CodexExecutableError,
                    "metadata raced with inspection",
                ):
                    _authenticate(
                        fixture,
                        FakeRunner(fixture),
                        filesystem_metadata_verifier=(
                            FakeFilesystemMetadataVerifier(inspect)
                        ),
                    )
            finally:
                os.chmod(fixture.source.parent, 0o700)
            self.assertTrue(changed)

    def test_directory_content_writes_between_metadata_windows_are_refreshed(
        self,
    ) -> None:
        with owned_temporary_directory("codex-directory-refresh-") as root:
            fixture = _build_fixture(root)
            observed_ctimes: list[int] = []

            def inspect(
                fd: int,
                path: pathlib.Path,
                _kind: str,
            ) -> ExtendedMetadataEvidence:
                if path == fixture.snapshot_parent:
                    observed_ctimes.append(os.fstat(fd).st_ctime_ns)
                return CLEAR_METADATA

            custody = _authenticate(
                fixture,
                FakeRunner(fixture),
                filesystem_metadata_verifier=FakeFilesystemMetadataVerifier(inspect),
            )
            _cleanup(custody)
            self.assertGreater(len(set(observed_ctimes)), 1)

    def test_seatbelt_policy_covers_every_ancestor_and_hardlink_alias(self) -> None:
        with owned_temporary_directory("codex-seatbelt-policy-") as root:
            snapshot_directory = root / "run" / "snapshots" / "private-snapshot"
            snapshot_directory.mkdir(parents=True, mode=0o700)
            policy = build_snapshot_seatbelt_policy(snapshot_directory)
            expected_ancestors = tuple(
                str(ancestor) for ancestor in reversed(snapshot_directory.parents)
            )

            self.assertEqual(policy.protected_ancestors, expected_ancestors)
            self.assertEqual(policy.rules.splitlines()[0], "(deny file-write*)")
            self.assertIn("(deny file-link)\n", policy.rules)
            for protected in (*expected_ancestors, str(snapshot_directory)):
                self.assertIn(
                    f'(deny file-write* (literal "{protected}"))',
                    policy.rules,
                )
            self.assertEqual(policy.rules.count("(subpath "), 1)
            self.assertIn(
                f'(deny file-write* (subpath "{snapshot_directory}"))',
                policy.rules,
            )
            self.assertEqual(
                policy.required_denials,
                (
                    "filesystem-write-default",
                    "write",
                    "unlink",
                    "rename",
                    "chmod",
                    "ancestor-relocation",
                    "hardlink-alias",
                    "firmlink-alias",
                ),
            )

    def test_seatbelt_default_denies_firmlink_alias_and_preserves_stdout(
        self,
    ) -> None:
        sandbox_exec = pathlib.Path("/usr/bin/sandbox-exec")
        if sys.platform != "darwin" or not sandbox_exec.is_file():
            self.skipTest("macOS sandbox-exec is unavailable")

        with owned_temporary_directory("codex-seatbelt-adversarial-") as root:
            run_root = root / "run"
            snapshot_parent = run_root / "snapshots"
            snapshot_directory = snapshot_parent / "private-snapshot"
            codex_home = run_root / "codex-home"
            temp_dir = run_root / "tmp"
            for directory in (
                snapshot_directory,
                codex_home,
                temp_dir,
            ):
                directory.mkdir(parents=True, mode=0o700)
            snapshot = snapshot_directory / "codex"
            snapshot.write_bytes(SYNTHETIC_BINARY)
            snapshot.chmod(SNAPSHOT_EXECUTABLE_MODE)
            policy = build_snapshot_seatbelt_policy(snapshot_directory)
            profile = "(version 1)\n(allow default)\n" + policy.rules

            def sandboxed(
                *argv: pathlib.Path | str,
            ) -> subprocess.CompletedProcess[bytes]:
                return subprocess.run(
                    (str(sandbox_exec), "-p", profile, *(str(item) for item in argv)),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5.0,
                    check=False,
                )

            baseline = sandboxed("/bin/echo", "seatbelt-stdout-ok")
            if (
                baseline.returncode == 71
                and baseline.stderr
                == b"sandbox-exec: sandbox_apply: Operation not permitted\n"
            ):
                self.skipTest("the outer sandbox forbids nested Seatbelt profiles")
            self.assertEqual(baseline.returncode, 0, baseline.stderr)
            self.assertEqual(baseline.stdout, b"seatbelt-stdout-ok\n")

            for ancestor in (
                snapshot_directory,
                snapshot_parent,
                run_root,
                root,
            ):
                destination = ancestor.with_name(ancestor.name + "-relocated")
                result = sandboxed("/bin/mv", ancestor, destination)
                if destination.exists() and not ancestor.exists():
                    os.rename(destination, ancestor)
                self.assertNotEqual(result.returncode, 0, ancestor)
                self.assertTrue(ancestor.is_dir())
                self.assertFalse(destination.exists())

            alias = codex_home / "codex-alias"
            self.assertNotEqual(
                sandboxed("/bin/ln", snapshot, alias).returncode,
                0,
            )
            self.assertFalse(alias.exists())

            home_state = codex_home / "state.json"
            temp_state = temp_dir / "session.tmp"
            self.assertNotEqual(
                sandboxed("/usr/bin/touch", home_state).returncode,
                0,
            )
            self.assertNotEqual(
                sandboxed("/usr/bin/touch", temp_state).returncode,
                0,
            )
            self.assertFalse(home_state.exists())
            self.assertFalse(temp_state.exists())

            data_alias = pathlib.Path("/System/Volumes/Data") / snapshot.relative_to(
                "/"
            )
            try:
                canonical_stat = os.stat(snapshot, follow_symlinks=False)
                alias_stat = os.stat(data_alias, follow_symlinks=False)
            except OSError as error:
                self.skipTest(f"macOS Data firmlink alias is unavailable: {error}")
            self.assertEqual(
                (canonical_stat.st_dev, canonical_stat.st_ino),
                (alias_stat.st_dev, alias_stat.st_ino),
            )
            alias_before = os.stat(data_alias, follow_symlinks=False)
            self.assertNotEqual(
                sandboxed("/bin/chmod", "700", data_alias).returncode,
                0,
            )
            self.assertNotEqual(
                sandboxed("/usr/bin/touch", data_alias).returncode,
                0,
            )
            alias_after = os.stat(data_alias, follow_symlinks=False)
            self.assertEqual(
                (
                    alias_before.st_mode,
                    alias_before.st_mtime_ns,
                    alias_before.st_ctime_ns,
                ),
                (
                    alias_after.st_mode,
                    alias_after.st_mtime_ns,
                    alias_after.st_ctime_ns,
                ),
            )

    def test_authenticates_source_into_private_snapshot_and_returns_both_fds(
        self,
    ) -> None:
        with owned_temporary_directory("codex-fixture-lifecycle-") as lifecycle_root:
            lifecycle_stat = lifecycle_root.stat(follow_symlinks=False)
            self.assertEqual(lifecycle_stat.st_uid, os.getuid())
            self.assertEqual(stat.S_IMODE(lifecycle_stat.st_mode), 0o700)
            self.assertFalse(
                lifecycle_root.is_relative_to(pathlib.Path(__file__).resolve().parent)
            )
        self.assertFalse(lifecycle_root.exists())

        with owned_temporary_directory("codex-executable-") as root:
            fixture = _build_fixture(root)
            runner = FakeRunner(fixture)
            custody = _authenticate(fixture, runner)
            snapshot_path = custody.snapshot_path
            try:
                evidence = custody.evidence
                self.assertEqual(evidence.sha256, _sha256(SYNTHETIC_BINARY))
                self.assertEqual(evidence.version, VERSION)
                self.assertEqual(
                    evidence.source_signature.team_identifier,
                    TEAM_IDENTIFIER,
                )
                self.assertEqual(evidence.signature.full_cdhash, FULL_CDHASH)
                self.assertTrue(evidence.capabilities.stdio)
                self.assertTrue(evidence.capabilities.strict_config)
                self.assertEqual(
                    evidence.capabilities.schema.sha256,
                    _sha256(SYNTHETIC_SCHEMA),
                )
                self.assertTrue(evidence.no_follow)
                self.assertFalse(evidence.fd_execution.supported)
                self.assertFalse(evidence.threat_boundary.fd_bound_exec_claimed)
                self.assertTrue(
                    evidence.threat_boundary.snapshot_path_is_only_launch_target
                )
                self.assertTrue(
                    evidence.threat_boundary.source_path_never_executed_after_fd_authentication
                )
                self.assertIn(
                    "already-compromised same-UID process",
                    evidence.threat_boundary.statement,
                )
                self.assertEqual(
                    evidence.threat_boundary.contained_subjects,
                    ("untrusted-reviewed-repository", "model-runtime"),
                )
                self.assertEqual(
                    evidence.threat_boundary.excluded_subjects,
                    (
                        "unrelated-already-compromised-same-uid-process",
                        "malicious-root-or-admin-tcb-member",
                    ),
                )
                self.assertNotEqual(snapshot_path, fixture.source)
                self.assertEqual(snapshot_path.parent.parent, fixture.snapshot_parent)
                self.assertTrue(
                    snapshot_path.parent.name.startswith(SNAPSHOT_DIRECTORY_PREFIX)
                )
                self.assertEqual(
                    stat.S_IMODE(snapshot_path.parent.stat().st_mode), 0o700
                )
                self.assertEqual(
                    stat.S_IMODE(snapshot_path.stat().st_mode),
                    SNAPSHOT_EXECUTABLE_MODE,
                )
                self.assertEqual(snapshot_path.stat().st_nlink, 1)
                self.assertEqual(
                    evidence.snapshot.executable_components[-1].path,
                    str(snapshot_path),
                )
                self.assertEqual(
                    evidence.snapshot.directory_components[-1].path,
                    str(snapshot_path.parent),
                )
                self.assertEqual(
                    evidence.snapshot.parent_components[-1].path,
                    str(fixture.snapshot_parent),
                )
                self.assertFalse(os.get_inheritable(custody.executable_fd))
                self.assertFalse(os.get_inheritable(custody.directory_fd))
                self.assertEqual(
                    os.pread(custody.executable_fd, len(SYNTHETIC_BINARY), 0),
                    SYNTHETIC_BINARY,
                )
                self.assertEqual(os.listdir(custody.directory_fd), ["codex"])
                launch_attestation = custody.attest_owner_snapshot_launch()
                self.assertEqual(
                    launch_attestation.executable_fd,
                    custody.executable_fd,
                )
                self.assertEqual(
                    launch_attestation.directory_fd,
                    custody.directory_fd,
                )
                self.assertEqual(launch_attestation.snapshot, evidence.snapshot)
                self.assertEqual(
                    launch_attestation.expected_sha256,
                    evidence.sha256,
                )
                self.assertEqual(
                    launch_attestation.revalidation.identity,
                    evidence.snapshot.executable_identity,
                )
                self.assertTrue(evidence.snapshot.copy.source_fd_only)
                self.assertTrue(evidence.snapshot.copy.file_fsynced)
                self.assertTrue(evidence.snapshot.copy.directory_fsynced)
                self.assertEqual(
                    [item.operation for item in evidence.identity_operations],
                    [
                        "source-sha256",
                        "source-codesign-strict-verification",
                        "source-codesign-metadata",
                        "snapshot-copy-from-source-fd",
                        "snapshot-codesign-strict-verification",
                        "snapshot-codesign-metadata",
                        "snapshot-version",
                        "snapshot-app-server-help",
                        "authentication-final-snapshot-sha256",
                    ],
                )
                self.assertNotIn(fixture.source, runner.executed_paths)
                self.assertEqual(set(runner.executed_paths), {snapshot_path})
                for _, timeout_seconds, max_output_bytes in runner.calls:
                    self.assertGreater(timeout_seconds, 0)
                    self.assertGreater(max_output_bytes, 0)
                self.assertFalse(
                    any("--verbose=6" in argv for argv, _, _ in runner.calls)
                )
                self.assertEqual(
                    sum(
                        argv[1:3] == ("--display", "--verbose=4")
                        for argv, _, _ in runner.calls
                    ),
                    2,
                )
                json.dumps(evidence.to_json(), sort_keys=True)
            finally:
                _cleanup(custody)
            self.assertTrue(custody.closed)
            self.assertFalse(snapshot_path.parent.exists())

    def test_rejects_non_absolute_source_without_path_lookup(self) -> None:
        with owned_temporary_directory("codex-relative-") as root:
            fixture = _build_fixture(root)
            runner = FakeRunner(fixture)
            with self.assertRaisesRegex(CodexExecutableError, "explicit absolute path"):
                authenticate_codex_executable(
                    pathlib.Path("codex"),
                    snapshot_parent=fixture.snapshot_parent,
                    exclusion_roots=fixture.roots,
                    aggregate_schema_path=fixture.schema,
                    command_runner=runner,
                    filesystem_metadata_verifier=FakeFilesystemMetadataVerifier(),
                    policy=fixture.policy,
                    platform_name="darwin",
                )
            self.assertEqual(runner.calls, [])

    def test_rejects_every_protected_source_descendant_class(self) -> None:
        with owned_temporary_directory("codex-excluded-") as root:
            fixture = _build_fixture(root)
            for label in ("repo", "helper", "runtime", "retention", "checkout"):
                with self.subTest(label=label):
                    values = {
                        name: getattr(fixture.roots, name)
                        for name in (
                            "repo",
                            "helper",
                            "runtime",
                            "retention",
                            "checkout",
                        )
                    }
                    values[label] = fixture.source.parent
                    runner = FakeRunner(fixture)
                    with self.assertRaisesRegex(
                        CodexExecutableError,
                        f"{label} exclusion root",
                    ):
                        _authenticate(
                            fixture,
                            runner,
                            exclusion_roots=ExecutableExclusionRoots(**values),
                        )
                    self.assertEqual(runner.calls, [])

    def test_rejects_darwin_data_firmlink_exclusion_aliases(self) -> None:
        canonical_source = pathlib.Path("/Users/alice/review/bin/codex")
        data_source = pathlib.Path("/System/Volumes/Data/Users/alice/review/bin/codex")
        canonical_root = pathlib.Path("/Users/alice/review")
        data_root = pathlib.Path("/System/Volumes/Data/Users/alice/review")
        object_keys = {
            "/": (1, 1),
            "/System": (1, 2),
            "/System/Volumes": (1, 3),
            "/System/Volumes/Data": (1, 4),
            "/Users": (1, 10),
            "/System/Volumes/Data/Users": (1, 10),
            "/Users/alice": (1, 11),
            "/System/Volumes/Data/Users/alice": (1, 11),
            "/Users/alice/review": (1, 12),
            "/System/Volumes/Data/Users/alice/review": (1, 12),
            "/Users/alice/review/bin": (1, 13),
            "/System/Volumes/Data/Users/alice/review/bin": (1, 13),
            "/Users/alice/review/bin/codex": (1, 14),
            "/System/Volumes/Data/Users/alice/review/bin/codex": (1, 14),
        }

        def synthetic_stat(
            path: os.PathLike[str] | str,
            *,
            follow_symlinks: bool = True,
        ) -> object:
            self.assertTrue(follow_symlinks)
            key = object_keys.get(os.fspath(path))
            if key is None:
                raise AssertionError(f"unexpected synthetic stat path: {path}")
            return mock.Mock(st_dev=key[0], st_ino=key[1])

        unrelated = {
            "helper": pathlib.Path("/unreached/helper"),
            "runtime": pathlib.Path("/unreached/runtime"),
            "retention": pathlib.Path("/unreached/retention"),
            "checkout": pathlib.Path("/unreached/checkout"),
        }
        cases = (
            (data_source, canonical_root),
            (canonical_source, data_root),
        )
        for source, root in cases:
            with (
                self.subTest(source=source, root=root),
                mock.patch.object(
                    codex_executable.os,
                    "stat",
                    side_effect=synthetic_stat,
                ),
                self.assertRaisesRegex(
                    ValueError,
                    "repo exclusion root.*path alias",
                ),
            ):
                codex_executable._validate_exclusions(
                    source,
                    ExecutableExclusionRoots(repo=root, **unrelated),
                )

    def test_rejects_symlink_leaf_and_component(self) -> None:
        with owned_temporary_directory("codex-symlink-") as root:
            fixture = _build_fixture(root)
            leaf = fixture.source.with_name("codex-link")
            os.symlink(fixture.source.name, leaf)
            component = root / "application-link"
            os.symlink(fixture.source.parent.name, component)
            for source in (leaf, component / fixture.source.name):
                with self.subTest(source=source):
                    changed = replace(fixture, source=source)
                    runner = FakeRunner(changed)
                    with self.assertRaisesRegex(
                        CodexExecutableError,
                        "(not a (regular file|directory)|group/world-writable)",
                    ):
                        _authenticate(changed, runner)
                    self.assertEqual(runner.calls, [])

    def test_rejects_writable_parent_unsafe_modes_and_wrong_owner(self) -> None:
        with owned_temporary_directory("codex-mode-") as root:
            fixture = _build_fixture(root)
            cases = (
                (fixture.source.parent, 0o770, "group/world-writable"),
                (fixture.source, 0o720, "group/world-writable"),
            )
            for target, mode, message in cases:
                with self.subTest(target=target, mode=oct(mode)):
                    os.chmod(fixture.source.parent, 0o700)
                    os.chmod(fixture.source, 0o700)
                    os.chmod(target, mode)
                    runner = FakeRunner(fixture)
                    with self.assertRaisesRegex(CodexExecutableError, message):
                        _authenticate(fixture, runner)
                    self.assertEqual(runner.calls, [])
            os.chmod(fixture.source.parent, 0o700)
            os.chmod(fixture.source, 0o700)
            if os.getuid() == 0:
                os.chown(fixture.source, 1, -1)
                wrong_owner_uid = 2
            else:
                wrong_owner_uid = os.getuid() + 10000
            runner = FakeRunner(fixture)
            with self.assertRaisesRegex(CodexExecutableError, "untrusted owner"):
                _authenticate(fixture, runner, owner_uid=wrong_owner_uid)

    def test_only_exact_root_admin_applications_directory_is_trusted(self) -> None:
        try:
            admin_gid = grp.getgrnam("admin").gr_gid
        except KeyError:
            self.skipTest("macOS admin group is unavailable")
        owner_uid = os.getuid()
        identity = replace(
            NodeIdentity.from_stat(os.stat("/")),
            mode=stat.S_IFDIR | 0o775,
            uid=0,
            gid=admin_gid,
        )
        with mock.patch.object(os, "getgroups", return_value=[admin_gid]):
            _validate_node(
                identity,
                path=pathlib.Path("/Applications"),
                kind="directory",
                owner_uid=owner_uid,
            )
            for path, changed in (
                (pathlib.Path("/Other"), identity),
                (
                    pathlib.Path("/Applications"),
                    replace(identity, mode=stat.S_IFDIR | 0o777),
                ),
                (
                    pathlib.Path("/Applications"),
                    replace(identity, gid=admin_gid + 10000),
                ),
            ):
                with self.subTest(path=path, mode=oct(changed.mode), gid=changed.gid):
                    with self.assertRaisesRegex(ValueError, "group/world-writable"):
                        _validate_node(
                            changed,
                            path=path,
                            kind="directory",
                            owner_uid=owner_uid,
                        )

    def test_metadata_policy_rejects_setid_nonregular_and_hardlinks(self) -> None:
        with owned_temporary_directory("codex-node-") as root:
            fixture = _build_fixture(root)
            identity = NodeIdentity.from_stat(os.stat(fixture.source))
            for permission in (stat.S_ISUID, stat.S_ISGID):
                with self.subTest(permission=oct(permission)):
                    with self.assertRaisesRegex(ValueError, "setuid/setgid"):
                        _validate_node(
                            replace(identity, mode=identity.mode | permission),
                            path=fixture.source,
                            kind="file",
                            owner_uid=os.getuid(),
                            require_executable=True,
                        )

            fifo = fixture.source.with_name("codex-fifo")
            link = fixture.source.with_name("codex-hardlink")
            fixture_parent_fd = os.open(
                fixture.source.parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                os.mkfifo(fifo, 0o700)
                fifo_object = _test_entry_object_identity(
                    os.stat(
                        os.fsencode(fifo.name),
                        dir_fd=fixture_parent_fd,
                        follow_symlinks=False,
                    )
                )
                changed = replace(fixture, source=fifo)
                try:
                    with self.assertRaisesRegex(
                        CodexExecutableError,
                        "not a regular file",
                    ):
                        _authenticate(changed, FakeRunner(changed))
                finally:
                    _remove_exact_test_entry(
                        fixture_parent_fd,
                        os.fsencode(fifo.name),
                        fifo_object,
                    )

                os.link(fixture.source, link)
                link_object = _test_entry_object_identity(
                    os.stat(
                        os.fsencode(link.name),
                        dir_fd=fixture_parent_fd,
                        follow_symlinks=False,
                    )
                )
                try:
                    with self.assertRaisesRegex(
                        CodexExecutableError,
                        "hard-link count",
                    ):
                        _authenticate(fixture, FakeRunner(fixture))
                finally:
                    _remove_exact_test_entry(
                        fixture_parent_fd,
                        os.fsencode(link.name),
                        link_object,
                    )
            finally:
                os.close(fixture_parent_fd)

    def test_rejects_acl_xattrs_and_quarantine_via_injected_inspector(self) -> None:
        with owned_temporary_directory("codex-extended-metadata-") as root:
            fixture = _build_fixture(root)
            cases = (
                ExtendedMetadataEvidence(
                    1,
                    (),
                    False,
                    ("group:unsafe:allow:write",),
                ),
                ExtendedMetadataEvidence(0, ("user.synthetic",), False),
                ExtendedMetadataEvidence(
                    0,
                    ("com.apple.quarantine",),
                    True,
                ),
            )
            for rejected in cases:
                with self.subTest(rejected=rejected):
                    verifier = FakeFilesystemMetadataVerifier(
                        lambda _fd, path, _kind, rejected=rejected: (
                            rejected if path == fixture.source else CLEAR_METADATA
                        )
                    )
                    runner = FakeRunner(fixture)
                    with self.assertRaisesRegex(
                        CodexExecutableError,
                        "ACLs, xattrs, and quarantine",
                    ):
                        _authenticate(
                            fixture,
                            runner,
                            filesystem_metadata_verifier=verifier,
                        )
                    self.assertEqual(runner.calls, [])

    def test_rejects_extended_metadata_created_on_snapshot(self) -> None:
        with owned_temporary_directory("codex-snapshot-xattr-") as root:
            fixture = _build_fixture(root)

            def inspect(
                _fd: int,
                path: pathlib.Path,
                kind: str,
            ) -> ExtendedMetadataEvidence:
                if kind == "file" and path.parent.name.startswith(
                    SNAPSHOT_DIRECTORY_PREFIX
                ):
                    return ExtendedMetadataEvidence(
                        0,
                        ("com.apple.quarantine",),
                        True,
                    )
                return CLEAR_METADATA

            with self.assertRaisesRegex(
                CodexExecutableError,
                "ACLs, xattrs, and quarantine",
            ):
                _authenticate(
                    fixture,
                    FakeRunner(fixture),
                    filesystem_metadata_verifier=FakeFilesystemMetadataVerifier(
                        inspect
                    ),
                )
            self.assertEqual(list(fixture.snapshot_parent.iterdir()), [])

    def test_rejects_digest_and_explicit_size_cap_mismatches(self) -> None:
        with owned_temporary_directory("codex-digest-") as root:
            fixture = _build_fixture(root)
            cases = (
                replace(fixture.policy, expected_sha256="0" * 64),
                replace(
                    fixture.policy,
                    max_executable_bytes=len(SYNTHETIC_BINARY) - 1,
                ),
            )
            for policy in cases:
                with self.subTest(policy=policy):
                    runner = FakeRunner(fixture)
                    with self.assertRaises(CodexExecutableError):
                        _authenticate(fixture, runner, policy=policy)
                    self.assertEqual(runner.calls, [])
                    self.assertEqual(list(fixture.snapshot_parent.iterdir()), [])

    def test_rejects_partial_fd_copy_and_removes_attempt_directory(self) -> None:
        with owned_temporary_directory("codex-partial-copy-") as root:
            fixture = _build_fixture(root)

            def partial_copy(
                source_fd: int,
                destination_fd: int,
                expected_size: int,
                max_bytes: int,
            ) -> SnapshotCopyResult:
                del max_bytes
                copied = os.pread(source_fd, expected_size // 2, 0)
                os.write(destination_fd, copied)
                return SnapshotCopyResult(len(copied), _sha256(copied))

            with self.assertRaisesRegex(CodexExecutableError, "incomplete"):
                _authenticate(
                    fixture,
                    FakeRunner(fixture),
                    snapshot_copier=partial_copy,
                )
            self.assertEqual(list(fixture.snapshot_parent.iterdir()), [])

    def test_rejects_source_swap_during_fd_copy(self) -> None:
        with owned_temporary_directory("codex-source-copy-swap-") as root:
            fixture = _build_fixture(root)
            swapped = False

            def swapping_copy(
                source_fd: int,
                destination_fd: int,
                expected_size: int,
                max_bytes: int,
            ) -> SnapshotCopyResult:
                nonlocal swapped
                swapped = True
                fixture.source.rename(fixture.source.with_name("codex-original"))
                fixture.source.write_bytes(b"replacement executable\n")
                os.chmod(fixture.source, 0o700)
                return copy_executable_from_fd(
                    source_fd,
                    destination_fd,
                    expected_size,
                    max_bytes,
                )

            with self.assertRaisesRegex(CodexExecutableError, "identity changed"):
                _authenticate(
                    fixture,
                    FakeRunner(fixture),
                    snapshot_copier=swapping_copy,
                )
            self.assertTrue(swapped)
            self.assertEqual(list(fixture.snapshot_parent.iterdir()), [])

    def test_source_timestamp_churn_does_not_replace_content_evidence(self) -> None:
        with owned_temporary_directory("codex-source-timestamp-") as root:
            fixture = _build_fixture(root)
            runner = FakeRunner(fixture)
            touched = False

            def touch_on_codesign(argv: tuple[str, ...]) -> None:
                nonlocal touched
                if argv[0] == CODESIGN_PATH and not touched:
                    touched = True
                    before = fixture.source.stat().st_mtime_ns
                    os.utime(
                        fixture.source,
                        ns=(before + 1_000_000, before + 1_000_000),
                    )

            runner.hook = touch_on_codesign
            custody = _authenticate(fixture, runner)
            _cleanup(custody)
            self.assertTrue(touched)

    def test_source_link_count_churn_is_not_a_content_mutation_signal(self) -> None:
        with owned_temporary_directory("codex-source-link-count-") as root:
            fixture = _build_fixture(root)
            runner = FakeRunner(fixture)
            alias = fixture.source.with_name("codex-hardlink")
            linked = False

            def link_on_codesign(argv: tuple[str, ...]) -> None:
                nonlocal linked
                if argv[0] == CODESIGN_PATH and not linked:
                    linked = True
                    os.link(fixture.source, alias)

            runner.hook = link_on_codesign
            custody = _authenticate(fixture, runner)
            try:
                self.assertEqual(fixture.source.stat().st_nlink, 2)
            finally:
                _cleanup(custody)
                alias.unlink()
            self.assertTrue(linked)

    def test_source_ancestor_child_entry_churn_preserves_identity(self) -> None:
        with owned_temporary_directory("codex-source-directory-churn-") as root:
            fixture = _build_fixture(root)
            runner = FakeRunner(fixture)
            child = fixture.source.parent / "benign-child"
            created = False

            def create_child_on_codesign(argv: tuple[str, ...]) -> None:
                nonlocal created
                if argv[0] == CODESIGN_PATH and not created:
                    created = True
                    child.write_bytes(b"benign directory churn\n")

            runner.hook = create_child_on_codesign
            custody = _authenticate(fixture, runner)
            _cleanup(custody)
            self.assertTrue(created)
            self.assertTrue(child.is_file())

    def test_rejects_same_size_source_content_change_during_codesign(self) -> None:
        with owned_temporary_directory("codex-source-content-change-") as root:
            fixture = _build_fixture(root)
            runner = FakeRunner(fixture)
            changed = False

            def change_on_codesign(argv: tuple[str, ...]) -> None:
                nonlocal changed
                if argv[0] == CODESIGN_PATH and not changed:
                    changed = True
                    fixture.source.write_bytes(b"x" * len(SYNTHETIC_BINARY))

            runner.hook = change_on_codesign
            with self.assertRaisesRegex(CodexExecutableError, "content changed"):
                _authenticate(fixture, runner)
            self.assertTrue(changed)
            self.assertEqual(list(fixture.snapshot_parent.iterdir()), [])

    def test_rejects_source_access_policy_change_during_codesign(self) -> None:
        with owned_temporary_directory("codex-source-mode-change-") as root:
            fixture = _build_fixture(root)
            runner = FakeRunner(fixture)
            changed = False

            def change_on_codesign(argv: tuple[str, ...]) -> None:
                nonlocal changed
                if argv[0] == CODESIGN_PATH and not changed:
                    changed = True
                    os.chmod(fixture.source, 0o500)

            runner.hook = change_on_codesign
            with self.assertRaisesRegex(CodexExecutableError, "identity changed"):
                _authenticate(fixture, runner)
            self.assertTrue(changed)
            self.assertEqual(list(fixture.snapshot_parent.iterdir()), [])

    def test_rejects_source_path_swap_during_codesign(self) -> None:
        with owned_temporary_directory("codex-source-codesign-swap-") as root:
            fixture = _build_fixture(root)
            runner = FakeRunner(fixture)
            swapped = False

            def swap_on_codesign(argv: tuple[str, ...]) -> None:
                nonlocal swapped
                if argv[0] == CODESIGN_PATH and not swapped:
                    swapped = True
                    fixture.source.rename(fixture.source.with_name("codex-original"))
                    fixture.source.write_bytes(b"replacement executable\n")
                    os.chmod(fixture.source, 0o700)

            runner.hook = swap_on_codesign
            with self.assertRaisesRegex(CodexExecutableError, "identity changed"):
                _authenticate(fixture, runner)
            self.assertTrue(swapped)
            self.assertEqual(list(fixture.snapshot_parent.iterdir()), [])

    def test_revalidation_distinguishes_missing_from_unreadable_path(self) -> None:
        with owned_temporary_directory("codex-revalidation-errors-") as root:
            fixture = _build_fixture(root)
            anchor = codex_executable._open_path_anchor(
                fixture.source,
                owner_uid=os.getuid(),
                leaf_kind="file",
                require_executable=True,
                filesystem_metadata_verifier=FakeFilesystemMetadataVerifier(),
            )
            try:
                with (
                    mock.patch.object(
                        codex_executable,
                        "_open_path_anchor",
                        side_effect=FileNotFoundError(
                            errno.ENOENT,
                            "synthetic missing path",
                        ),
                    ),
                    self.assertRaisesRegex(
                        ValueError,
                        "path is missing during revalidation",
                    ),
                ):
                    codex_executable._assert_anchor_stable(anchor)

                with (
                    mock.patch.object(
                        codex_executable,
                        "_open_path_anchor",
                        side_effect=PermissionError(
                            errno.EACCES,
                            "synthetic unreadable path",
                        ),
                    ),
                    self.assertRaisesRegex(
                        OSError,
                        "path could not be revalidated",
                    ) as raised,
                ):
                    codex_executable._assert_anchor_stable(anchor)
                self.assertEqual(raised.exception.errno, errno.EACCES)
            finally:
                os.close(anchor.fd)

    def test_rejects_staged_codesign_and_version_mismatches(self) -> None:
        with owned_temporary_directory("codex-staged-probes-") as root:
            fixture = _build_fixture(root)

            codesign_runner = FakeRunner(fixture)
            codesign_runner.snapshot_metadata = (
                f"CandidateCDHashFull sha256={'b' * 64}\n"
                f"TeamIdentifier={TEAM_IDENTIFIER}\n"
            ).encode("ascii")
            with self.assertRaisesRegex(CodexExecutableError, "full CDHash mismatch"):
                _authenticate(fixture, codesign_runner)
            self.assertEqual(list(fixture.snapshot_parent.iterdir()), [])

            version_runner = FakeRunner(fixture)
            version_runner.version = b"codex-cli 0.145.0-alpha.19\n"
            with self.assertRaisesRegex(CodexExecutableError, "pinned version"):
                _authenticate(fixture, version_runner)
            self.assertEqual(list(fixture.snapshot_parent.iterdir()), [])

    def test_accepts_only_the_exact_desktop_path_alias_warning(self) -> None:
        warning = (
            b"WARNING: proceeding, even though we could not create PATH aliases: "
            b"Operation not permitted (os error 1)\n"
        )
        with owned_temporary_directory("codex-probe-warning-") as root:
            fixture = _build_fixture(root)
            for attribute in (
                "version_stderr",
                "help_stderr",
                "schema_stderr",
            ):
                with self.subTest(attribute=attribute):
                    runner = FakeRunner(fixture)
                    setattr(runner, attribute, warning)
                    custody = _authenticate(fixture, runner)
                    _cleanup(custody)

            runner = FakeRunner(fixture)
            runner.version_stderr = warning + b"unexpected\n"
            with self.assertRaisesRegex(CodexExecutableError, "did not complete"):
                _authenticate(fixture, runner)
            self.assertEqual(list(fixture.snapshot_parent.iterdir()), [])

    def test_rejects_help_schema_and_symlinked_schema_mismatches(self) -> None:
        with owned_temporary_directory("codex-capability-probes-") as root:
            fixture = _build_fixture(root)
            help_runner = FakeRunner(fixture)
            help_runner.help = b"Options:\n      --stdio\n"
            with self.assertRaisesRegex(CodexExecutableError, "required options"):
                _authenticate(fixture, help_runner)
            self.assertEqual(list(fixture.snapshot_parent.iterdir()), [])

            fixture.schema.write_bytes(b"wrong schema\n")
            os.chmod(fixture.schema, 0o600)
            with self.assertRaisesRegex(CodexExecutableError, "schema digest"):
                _authenticate(fixture, FakeRunner(fixture))
            self.assertEqual(list(fixture.snapshot_parent.iterdir()), [])

            fixture.schema.write_bytes(SYNTHETIC_SCHEMA)
            os.chmod(fixture.schema, 0o600)
            real_schema = fixture.schema.with_name("schema-real.json")
            fixture.schema.rename(real_schema)
            os.symlink(real_schema.name, fixture.schema)
            with self.assertRaisesRegex(
                CodexExecutableError,
                "(not a regular file|group/world-writable)",
            ):
                _authenticate(fixture, FakeRunner(fixture))
            self.assertEqual(list(fixture.snapshot_parent.iterdir()), [])

    def test_rejects_duplicated_or_malformed_codesign_output(self) -> None:
        with owned_temporary_directory("codex-codesign-parse-") as root:
            fixture = _build_fixture(root)
            valid_hash = f"CandidateCDHashFull sha256={FULL_CDHASH}\n".encode("ascii")
            valid_team = f"TeamIdentifier={TEAM_IDENTIFIER}\n".encode("ascii")
            cases = (
                valid_hash + valid_team + valid_team,
                valid_hash + valid_hash + valid_team,
                valid_hash + b"TeamIdentifier=2DC432GLL2 trailing\n",
                b"CandidateCDHashFull sha256=abcd\n" + valid_team,
                valid_hash + b"TeamIdentifier=not-set\n",
            )
            for metadata in cases:
                with self.subTest(metadata=metadata):
                    runner = FakeRunner(fixture)
                    runner.source_metadata = metadata
                    with self.assertRaises(CodexExecutableError):
                        _authenticate(fixture, runner)
                    self.assertEqual(list(fixture.snapshot_parent.iterdir()), [])

    def test_injected_codesign_metadata_verifier_is_pinned_twice(self) -> None:
        with owned_temporary_directory("codex-metadata-injected-") as root:
            fixture = _build_fixture(root)
            runner = FakeRunner(fixture)
            runner.source_metadata = b"synthetic source metadata\n"
            runner.snapshot_metadata = b"synthetic snapshot metadata\n"
            verifier = mock.Mock(
                return_value=SignatureMetadata(TEAM_IDENTIFIER, FULL_CDHASH)
            )
            custody = _authenticate(
                fixture,
                runner,
                metadata_verifier=verifier,
            )
            _cleanup(custody)
            self.assertEqual(verifier.call_count, 2)

            bad_verifier = mock.Mock(
                side_effect=(
                    SignatureMetadata(TEAM_IDENTIFIER, FULL_CDHASH),
                    SignatureMetadata("AAAAAAAAAA", FULL_CDHASH),
                )
            )
            with self.assertRaisesRegex(
                CodexExecutableError, "TeamIdentifier mismatch"
            ):
                _authenticate(
                    fixture,
                    FakeRunner(fixture),
                    metadata_verifier=bad_verifier,
                )
            self.assertEqual(list(fixture.snapshot_parent.iterdir()), [])

    def test_generates_schema_only_by_executing_private_snapshot(self) -> None:
        with owned_temporary_directory("codex-schema-generated-") as root:
            fixture = _build_fixture(root)
            runner = FakeRunner(fixture)
            schema_work_root = root / "schema-work"
            schema_work_root.mkdir(mode=0o700)
            custody = _authenticate(
                fixture,
                runner,
                aggregate_schema_path=None,
                schema_work_root=schema_work_root,
            )
            snapshot_path = custody.snapshot_path
            try:
                schema = custody.evidence.capabilities.schema
                self.assertEqual(schema.source, "generated")
                self.assertIsNotNone(schema.generation_command)
                self.assertEqual(schema.sha256, _sha256(SYNTHETIC_SCHEMA))
                self.assertEqual(set(runner.executed_paths), {snapshot_path})
                self.assertNotIn(fixture.source, runner.executed_paths)
                self.assertIn(
                    "app-server-generate-json-schema",
                    [item.operation for item in custody.evidence.identity_operations],
                )
            finally:
                _cleanup(custody)
            self.assertEqual(list(schema_work_root.iterdir()), [])

    def test_generated_schema_work_root_result_interrupt_closes_owned_anchor(
        self,
    ) -> None:
        with owned_temporary_directory("codex-schema-root-result-") as root:
            schema_work_root = root / "schema-work"
            schema_work_root.mkdir(mode=0o700)
            opened: list[codex_executable._PathAnchor] = []
            original_open = codex_executable._open_path_anchor
            target_offset = _call_result_store_offset(
                codex_executable._generate_schema,
                called_name="_open_path_anchor",
                stored_name="work_root",
            )
            interruption = KeyboardInterrupt(
                "injected schema work-root CALL-to-STORE interrupt"
            )
            injected = False

            def recording_open(
                *args: object,
                **kwargs: object,
            ) -> codex_executable._PathAnchor:
                anchor = original_open(*args, **kwargs)
                if kwargs.get("result_owner") is not None:
                    opened.append(anchor)
                return anchor

            def interrupt_result_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is codex_executable._generate_schema.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_result_store

            previous_trace = sys.gettrace()
            try:
                with mock.patch.object(
                    codex_executable,
                    "_open_path_anchor",
                    side_effect=recording_open,
                ):
                    sys.settrace(interrupt_result_store)
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        codex_executable._generate_schema(
                            source_anchor=mock.sentinel.source_anchor,
                            operations=[],
                            schema_work_root=schema_work_root,
                            command_runner=mock.Mock(
                                side_effect=AssertionError(
                                    "schema command must not run"
                                )
                            ),
                            owner_uid=os.getuid(),
                            policy=CodexExecutablePolicy(),
                        )
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(injected)
            self.assertIs(caught.exception, interruption)
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError) as raised:
                os.fstat(opened[0].fd)
            self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_generated_schema_output_result_interrupt_closes_both_anchors(
        self,
    ) -> None:
        with owned_temporary_directory("codex-schema-output-result-") as root:
            schema_work_root = root / "schema-work"
            schema_work_root.mkdir(mode=0o700)
            opened: list[codex_executable._PathAnchor] = []
            original_open = codex_executable._open_path_anchor
            target_offset = _call_result_store_offset(
                codex_executable._generate_schema,
                called_name="_open_path_anchor",
                stored_name="output_anchor",
            )
            interruption = KeyboardInterrupt(
                "injected schema output CALL-to-STORE interrupt"
            )
            injected = False

            def recording_open(
                *args: object,
                **kwargs: object,
            ) -> codex_executable._PathAnchor:
                anchor = original_open(*args, **kwargs)
                if kwargs.get("result_owner") is not None:
                    opened.append(anchor)
                return anchor

            def interrupt_result_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is codex_executable._generate_schema.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_result_store

            previous_trace = sys.gettrace()
            try:
                with mock.patch.object(
                    codex_executable,
                    "_open_path_anchor",
                    side_effect=recording_open,
                ):
                    sys.settrace(interrupt_result_store)
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        codex_executable._generate_schema(
                            source_anchor=mock.sentinel.source_anchor,
                            operations=[],
                            schema_work_root=schema_work_root,
                            command_runner=mock.Mock(
                                side_effect=AssertionError(
                                    "schema command must not run"
                                )
                            ),
                            owner_uid=os.getuid(),
                            policy=CodexExecutablePolicy(),
                        )
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(injected)
            self.assertIs(caught.exception, interruption)
            self.assertEqual(
                len(opened),
                2,
                [(str(anchor.path), anchor.fd) for anchor in opened],
            )
            self.assertEqual(list(schema_work_root.iterdir()), [])
            for anchor in opened:
                with self.assertRaises(OSError) as raised:
                    os.fstat(anchor.fd)
                self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_schema_process_closure_failure_retains_output_and_custody(
        self,
    ) -> None:
        with owned_temporary_directory("codex-schema-process-retain-") as root:
            fixture = _build_fixture(root)
            schema_work_root = root / "schema-work"
            schema_work_root.mkdir(mode=0o700)
            runner = FakeRunner(fixture)
            marker_name = "process-owned-evidence.txt"

            def fail_schema_with_unproven_closure(argv: tuple[str, ...]) -> None:
                if argv[1:4] != (
                    "app-server",
                    "generate-json-schema",
                    "--out",
                ):
                    return
                output = pathlib.Path(argv[4])
                (output / marker_name).write_text(
                    "retain process evidence",
                    encoding="ascii",
                )
                raise PreflightProcessClosureUnproven(
                    "synthetic schema closure is unproven",
                    evidence=codex_executable.PreflightProcessClosureEvidence(
                        leader_pid=424242,
                        leader_pgid=424242,
                        leader_session_id=424242,
                        leader_start_identity="synthetic-start",
                        profile_sha256="a" * 64,
                        leader_reaped=False,
                        stdio_closed=False,
                        authenticated_no_child_profile=True,
                        permitted_process_closure_proven=False,
                        process_group_emptiness_used_as_descendant_proof=False,
                        reason="synthetic retained schema leader",
                    ),
                )

            runner.hook = fail_schema_with_unproven_closure
            with self.assertRaises(PreflightProcessClosureUnproven) as caught:
                _authenticate(
                    fixture,
                    runner,
                    aggregate_schema_path=None,
                    schema_work_root=schema_work_root,
                )

            generated = next(
                resource
                for resource in caught.exception.retained_resources
                if isinstance(
                    resource,
                    codex_executable._RetainedGeneratedSchema,
                )
            )
            staged = next(
                resource
                for resource in caught.exception.retained_resources
                if isinstance(resource, codex_executable._StagedSnapshot)
            )
            try:
                self.assertEqual(
                    (
                        generated.work_root.path / generated.output_name / marker_name
                    ).read_text(encoding="ascii"),
                    "retain process evidence",
                )
                os.fstat(generated.work_root.fd)
                assert generated.output_anchor is not None
                os.fstat(generated.output_anchor.fd)
                os.fstat(staged.directory_anchor.fd)
                os.fstat(staged.file_anchor.fd)
                self.assertIn(
                    "generated-schema",
                    {evidence.stage for evidence in caught.exception.recovery_evidence},
                )
                self.assertIn(
                    "authentication-retention",
                    {evidence.stage for evidence in caught.exception.recovery_evidence},
                )
            finally:
                generated.close_descriptors_for_recovery()
                codex_executable._close_staged_snapshot_fds(staged)

    def test_generated_schema_mkdir_result_interrupt_retains_candidate_custody(
        self,
    ) -> None:
        with owned_temporary_directory("codex-schema-mkdir-result-") as root:
            fixture = _build_fixture(root)
            schema_work_root = root / "schema-work"
            schema_work_root.mkdir(mode=0o700)
            source_anchor = codex_executable._open_path_anchor(
                fixture.source,
                owner_uid=os.getuid(),
                leaf_kind="file",
                require_executable=True,
            )
            target_offset = _call_result_next_opcode_offset(
                codex_executable._generate_schema,
                called_name="mkdir",
            )
            interruption = KeyboardInterrupt(
                "injected generated-schema mkdir result interrupt"
            )
            injected = False

            def interrupt_mkdir_result(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is codex_executable._generate_schema.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_mkdir_result

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_mkdir_result)
                with self.assertRaises(CodexExecutableRetentionRequired) as caught:
                    codex_executable._generate_schema(
                        source_anchor=source_anchor,
                        operations=[],
                        schema_work_root=schema_work_root,
                        command_runner=FakeRunner(fixture),
                        owner_uid=os.getuid(),
                        policy=fixture.policy,
                    )
            finally:
                sys.settrace(previous_trace)

            generated = next(
                resource
                for resource in caught.exception.retained_resources
                if isinstance(
                    resource,
                    codex_executable._RetainedGeneratedSchema,
                )
            )
            try:
                self.assertTrue(injected)
                self.assertIs(caught.exception.__context__, interruption)
                self.assertEqual(
                    caught.exception.failure.code,
                    "generated-schema-custody-unavailable",
                )
                self.assertEqual(
                    generated.creation_outcome,
                    "mkdir-outcome-unproven",
                )
                self.assertIsNone(generated.output_anchor)
                os.fstat(generated.work_root.fd)
                self.assertTrue(
                    (generated.work_root.path / generated.output_name).is_dir()
                )
                evidence = next(
                    item
                    for item in caught.exception.recovery_evidence
                    if isinstance(
                        item,
                        codex_executable.CodexExecutableRecoveryEvidence,
                    )
                )
                self.assertIn(
                    "creation_outcome=mkdir-outcome-unproven",
                    evidence.reason,
                )
            finally:
                generated.close_descriptors_for_recovery()
                os.close(source_anchor.fd)

    def test_generated_schema_retention_publication_interrupt_keeps_one_owner(
        self,
    ) -> None:
        for window, target_offset in (
            (
                "owner-construction-result",
                _call_result_offset_with_argument(
                    codex_executable._generate_schema,
                    called_name="_generated_schema_retention_owner",
                    argument_name="error",
                    following_opname="STORE_FAST",
                    following_argval="retention_owner",
                ),
            ),
            (
                "publication-result",
                _call_result_offset_with_argument(
                    codex_executable._generate_schema,
                    called_name="_finish_generated_schema_retention",
                    argument_name="error",
                    following_opname="POP_TOP",
                ),
            ),
        ):
            with (
                self.subTest(window=window),
                owned_temporary_directory(
                    "codex-schema-retention-publication-"
                ) as root,
            ):
                fixture = _build_fixture(root)
                schema_work_root = root / "schema-work"
                schema_work_root.mkdir(mode=0o700)
                runner = FakeRunner(fixture)
                interruption = KeyboardInterrupt(
                    f"injected generated-schema {window} interrupt"
                )
                injected = False
                source_error = PreflightProcessClosureUnproven(
                    "synthetic schema closure is unproven",
                    evidence=codex_executable.PreflightProcessClosureEvidence(
                        leader_pid=424242,
                        leader_pgid=424242,
                        leader_session_id=424242,
                        leader_start_identity="synthetic-start",
                        profile_sha256="a" * 64,
                        leader_reaped=False,
                        stdio_closed=False,
                        authenticated_no_child_profile=True,
                        permitted_process_closure_proven=False,
                        process_group_emptiness_used_as_descendant_proof=False,
                        reason="synthetic retained schema leader",
                    ),
                )

                def fail_schema(argv: tuple[str, ...]) -> None:
                    if argv[1:4] == (
                        "app-server",
                        "generate-json-schema",
                        "--out",
                    ):
                        raise source_error

                def interrupt_publication(
                    frame: object,
                    event: str,
                    _argument: object,
                ) -> object:
                    nonlocal injected
                    if (
                        getattr(frame, "f_code", None)
                        is codex_executable._generate_schema.__code__
                    ):
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not injected
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == target_offset
                        ):
                            injected = True
                            raise interruption
                    return interrupt_publication

                runner.hook = fail_schema
                previous_trace = sys.gettrace()
                try:
                    sys.settrace(interrupt_publication)
                    with self.assertRaises(PreflightProcessClosureUnproven) as caught:
                        _authenticate(
                            fixture,
                            runner,
                            aggregate_schema_path=None,
                            schema_work_root=schema_work_root,
                        )
                finally:
                    sys.settrace(previous_trace)

                generated = tuple(
                    resource
                    for resource in caught.exception.retained_resources
                    if isinstance(
                        resource,
                        codex_executable._RetainedGeneratedSchema,
                    )
                )
                staged = tuple(
                    resource
                    for resource in caught.exception.retained_resources
                    if isinstance(resource, codex_executable._StagedSnapshot)
                )
                try:
                    self.assertTrue(injected)
                    self.assertIs(caught.exception, source_error)
                    self.assertEqual(
                        caught.exception.retention_publication_errors,
                        (interruption,),
                    )
                    self.assertEqual(len(generated), 1)
                    self.assertEqual(len(staged), 1)
                    self.assertEqual(generated[0].creation_outcome, "descriptor-bound")
                    os.fstat(generated[0].work_root.fd)
                    assert generated[0].output_anchor is not None
                    os.fstat(generated[0].output_anchor.fd)
                    generated_evidence = tuple(
                        item
                        for item in caught.exception.recovery_evidence
                        if isinstance(
                            item,
                            codex_executable.CodexExecutableRecoveryEvidence,
                        )
                        and item.stage == "generated-schema"
                    )
                    self.assertEqual(len(generated_evidence), 1)
                finally:
                    for resource in generated:
                        resource.close_descriptors_for_recovery()
                    for resource in staged:
                        codex_executable._close_staged_snapshot_fds(resource)

    def test_retained_generated_schema_close_abandons_reused_same_object_fd(
        self,
    ) -> None:
        with owned_temporary_directory("codex-schema-close-reuse-") as root:
            work_root_path = root / "schema-work"
            work_root_path.mkdir(mode=0o700)
            output_path = work_root_path / "generated"
            output_path.mkdir(mode=0o700)
            work_root = codex_executable._open_path_anchor(
                work_root_path,
                owner_uid=os.getuid(),
                leaf_kind="directory",
                require_executable=False,
            )
            output_anchor = codex_executable._open_path_anchor(
                output_path,
                owner_uid=os.getuid(),
                leaf_kind="directory",
                require_executable=False,
            )
            retained = codex_executable._RetainedGeneratedSchema(
                work_root=work_root,
                output_name=output_path.name,
                output_anchor=output_anchor,
                creation_outcome="descriptor-bound",
            )
            original_output_fd = output_anchor.fd
            target_offset = _call_result_next_opcode_offset(
                codex_executable._RetainedGeneratedSchema.close_descriptors_for_recovery,
                called_name="close",
            )
            interruption = KeyboardInterrupt(
                "injected generated-schema descriptor close result interrupt"
            )
            injected = False
            reused_fd: int | None = None

            def interrupt_and_reopen_same_root(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected, reused_fd
                if (
                    getattr(frame, "f_code", None)
                    is codex_executable._RetainedGeneratedSchema.close_descriptors_for_recovery.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        candidate_fd = os.open(
                            output_path,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        )
                        if candidate_fd != original_output_fd:
                            os.dup2(
                                candidate_fd,
                                original_output_fd,
                                inheritable=False,
                            )
                            os.close(candidate_fd)
                            candidate_fd = original_output_fd
                        reused_fd = candidate_fd
                        raise interruption
                return interrupt_and_reopen_same_root

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_and_reopen_same_root)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    retained.close_descriptors_for_recovery()
            finally:
                sys.settrace(previous_trace)

            try:
                self.assertTrue(injected)
                self.assertIs(caught.exception, interruption)
                self.assertEqual(reused_fd, original_output_fd)
                self.assertEqual(retained._output_fd, original_output_fd)
                self.assertEqual(
                    retained._descriptor_close_outcomes["_output_fd"],
                    "unproven",
                )
                self.assertIsNotNone(retained._work_root_fd)
                retained.close_descriptors_for_recovery()
                self.assertIsNone(retained._work_root_fd)
                assert reused_fd is not None
                os.fstat(reused_fd)
                retained.close_descriptors_for_recovery()
                os.fstat(reused_fd)
            finally:
                if reused_fd is not None:
                    os.close(reused_fd)

    def test_retained_generated_schema_close_pre_call_interrupt_keeps_evidence(
        self,
    ) -> None:
        with owned_temporary_directory("codex-schema-close-pre-call-") as root:
            work_root_path = root / "schema-work"
            work_root_path.mkdir(mode=0o700)
            output_path = work_root_path / "generated"
            output_path.mkdir(mode=0o700)
            work_root = codex_executable._open_path_anchor(
                work_root_path,
                owner_uid=os.getuid(),
                leaf_kind="directory",
                require_executable=False,
            )
            output_anchor = codex_executable._open_path_anchor(
                output_path,
                owner_uid=os.getuid(),
                leaf_kind="directory",
                require_executable=False,
            )
            retained = codex_executable._RetainedGeneratedSchema(
                work_root=work_root,
                output_name=output_path.name,
                output_anchor=output_anchor,
                creation_outcome="descriptor-bound",
            )
            original_output_fd = output_anchor.fd
            target_offset = _call_opcode_offset(
                codex_executable._RetainedGeneratedSchema.close_descriptors_for_recovery,
                called_name="close",
            )
            interruption = KeyboardInterrupt(
                "injected generated-schema descriptor pre-close interrupt"
            )
            injected = False

            def interrupt_before_close(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is codex_executable._RetainedGeneratedSchema.close_descriptors_for_recovery.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_before_close

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_before_close)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    retained.close_descriptors_for_recovery()
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(injected)
            self.assertIs(caught.exception, interruption)
            self.assertIs(
                caught.exception.retained_generated_schema_close_owner,
                retained,
            )
            self.assertEqual(retained._output_fd, original_output_fd)
            self.assertEqual(
                retained._descriptor_close_outcomes["_output_fd"],
                "unproven",
            )
            os.fstat(original_output_fd)
            retained.close_descriptors_for_recovery()
            os.fstat(original_output_fd)
            os.close(original_output_fd)

    def test_path_anchor_close_pre_call_interrupt_retains_result_owner(
        self,
    ) -> None:
        with owned_temporary_directory("codex-anchor-close-pre-call-") as root:
            anchor = codex_executable._open_path_anchor(
                root,
                owner_uid=os.getuid(),
                leaf_kind="directory",
                require_executable=False,
            )
            owner = codex_executable._PathAnchorResultOwner(anchor=anchor)
            target_offset = _call_opcode_offset(
                codex_executable._PathAnchorResultOwner.close,
                called_name="close",
            )
            interruption = KeyboardInterrupt(
                "injected path-anchor descriptor pre-close interrupt"
            )
            injected = False

            def interrupt_before_close(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is codex_executable._PathAnchorResultOwner.close.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_before_close

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_before_close)
                with self.assertRaises(KeyboardInterrupt) as caught:
                    owner.close()
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(injected)
            self.assertIs(caught.exception, interruption)
            self.assertIs(caught.exception.path_anchor_close_result_owner, owner)
            self.assertIs(owner.anchor, anchor)
            self.assertEqual(owner.close_outcome, "unproven")
            os.fstat(anchor.fd)
            owner.close()
            os.fstat(anchor.fd)
            os.close(anchor.fd)

    def test_snapshot_stability_file_open_failure_closes_reopened_directory(
        self,
    ) -> None:
        with owned_temporary_directory("codex-snapshot-open-rollback-") as root:
            fixture = _build_fixture(root)
            custody = _authenticate(fixture, FakeRunner(fixture))
            staged = custody._staged
            original_open = codex_executable._open_path_anchor
            reopened_directory_fd: int | None = None
            calls = 0

            def fail_file_open(*args: object, **kwargs: object) -> object:
                nonlocal calls, reopened_directory_fd
                calls += 1
                if calls == 2:
                    raise OSError(errno.EIO, "injected snapshot file open failure")
                anchor = original_open(*args, **kwargs)
                reopened_directory_fd = anchor.fd
                return anchor

            with (
                mock.patch.object(
                    codex_executable,
                    "_open_path_anchor",
                    side_effect=fail_file_open,
                ),
                self.assertRaisesRegex(OSError, "snapshot file open failure"),
            ):
                codex_executable._assert_snapshot_stable(
                    staged.directory_anchor,
                    staged.file_anchor,
                )

            assert reopened_directory_fd is not None
            with self.assertRaises(OSError) as raised:
                os.fstat(reopened_directory_fd)
            self.assertEqual(raised.exception.errno, errno.EBADF)
            _cleanup(custody)

    def test_authentication_rollback_failure_retains_snapshot_fds_and_evidence(
        self,
    ) -> None:
        with owned_temporary_directory("codex-auth-rollback-retain-") as root:
            fixture = _build_fixture(root)
            runner = FakeRunner(fixture)
            runner.version = b"unexpected-version\n"
            with (
                mock.patch.object(
                    codex_executable,
                    "_destroy_staged_snapshot",
                    side_effect=OSError(errno.EIO, "injected rollback refusal"),
                ),
                self.assertRaises(CodexExecutableRetentionRequired) as caught,
            ):
                _authenticate(fixture, runner)

            staged = next(
                resource
                for resource in caught.exception.retained_resources
                if isinstance(resource, codex_executable._StagedSnapshot)
            )
            try:
                os.fstat(staged.directory_anchor.fd)
                os.fstat(staged.file_anchor.fd)
                self.assertTrue(staged.directory_anchor.path.is_dir())
                self.assertTrue(staged.file_anchor.path.is_file())
                evidence = next(
                    evidence
                    for evidence in caught.exception.recovery_evidence
                    if evidence.stage == "authentication-rollback"
                )
                self.assertEqual(
                    evidence.directory_fd,
                    staged.directory_anchor.fd,
                )
                self.assertEqual(evidence.executable_fd, staged.file_anchor.fd)
                self.assertIn("injected rollback refusal", evidence.reason)
            finally:
                codex_executable._close_staged_snapshot_fds(staged)

    def test_snapshot_mkdir_result_gap_cleans_with_typed_evidence(self) -> None:
        target_offset = _call_result_next_opcode_offset(
            codex_executable._create_and_publish_snapshot_directory,
            called_name="mkdir",
        )
        interruption_cases = (
            KeyboardInterrupt("injected snapshot mkdir result interrupt"),
            SystemExit("injected snapshot mkdir result exit"),
        )
        for interruption in interruption_cases:
            with (
                self.subTest(interruption=type(interruption).__name__),
                owned_temporary_directory(
                    f"codex-snapshot-mkdir-{type(interruption).__name__}-"
                ) as root,
            ):
                fixture = _build_fixture(root)
                injected = False

                def interrupt_mkdir_result(
                    frame: object,
                    event: str,
                    _argument: object,
                ) -> object:
                    nonlocal injected
                    if (
                        getattr(frame, "f_code", None)
                        is codex_executable._create_and_publish_snapshot_directory.__code__
                    ):
                        setattr(frame, "f_trace_opcodes", True)
                        if (
                            not injected
                            and event == "opcode"
                            and getattr(frame, "f_lasti", None) == target_offset
                        ):
                            injected = True
                            raise interruption
                    return interrupt_mkdir_result

                previous_trace = sys.gettrace()
                try:
                    sys.settrace(interrupt_mkdir_result)
                    with self.assertRaises(
                        codex_executable.CodexExecutableSnapshotCreationAborted
                    ) as caught:
                        _authenticate(fixture, FakeRunner(fixture))
                finally:
                    sys.settrace(previous_trace)

                self.assertTrue(injected)
                self.assertIs(caught.exception.__cause__, interruption)
                self.assertEqual(list(fixture.snapshot_parent.iterdir()), [])
                evidence = caught.exception.evidence
                self.assertEqual(evidence.operation, "mkdir-directory")
                self.assertEqual(evidence.entry_state, "removed")
                self.assertTrue(evidence.directory_removed)
                self.assertTrue(evidence.parent_fsynced)
                self.assertTrue(
                    evidence.directory_name.startswith(SNAPSHOT_DIRECTORY_PREFIX)
                )

    def test_snapshot_creation_identity_stat_failure_cleans_with_typed_evidence(
        self,
    ) -> None:
        with owned_temporary_directory("codex-snapshot-identity-stat-") as root:
            fixture = _build_fixture(root)
            original_stat = os.stat
            failed = False

            def fail_creation_identity_stat(
                path: object,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                nonlocal failed
                if (
                    not failed
                    and kwargs.get("dir_fd") is not None
                    and kwargs.get("follow_symlinks") is False
                    and os.fsdecode(path).startswith(SNAPSHOT_DIRECTORY_PREFIX)
                ):
                    failed = True
                    raise OSError(
                        errno.EIO,
                        "injected snapshot creation identity stat failure",
                    )
                return original_stat(path, *args, **kwargs)

            with (
                mock.patch.object(
                    codex_executable.os,
                    "stat",
                    side_effect=fail_creation_identity_stat,
                ),
                self.assertRaises(
                    codex_executable.CodexExecutableSnapshotCreationAborted
                ) as caught,
            ):
                _authenticate(fixture, FakeRunner(fixture))

            self.assertTrue(failed)
            self.assertEqual(list(fixture.snapshot_parent.iterdir()), [])
            self.assertEqual(
                caught.exception.evidence.operation,
                "capture-directory-identity",
            )
            self.assertEqual(caught.exception.evidence.entry_state, "removed")
            self.assertTrue(caught.exception.evidence.directory_removed)
            self.assertTrue(caught.exception.evidence.parent_fsynced)

    def test_new_snapshot_rollback_scopes_object_content_and_access_policy(
        self,
    ) -> None:
        cases = ("content", "object", "access-policy")
        for mutation in cases:
            with (
                self.subTest(mutation=mutation),
                owned_temporary_directory(f"codex-new-snapshot-{mutation}-") as root,
            ):
                fixture = _build_fixture(root)

                def fail_copy(
                    _source_fd: int,
                    destination_fd: int,
                    _expected_size: int,
                    _max_bytes: int,
                ) -> SnapshotCopyResult:
                    if mutation == "content":
                        os.write(destination_fd, b"partial untrusted content")
                    elif mutation == "object":
                        snapshot_directory = next(
                            path
                            for path in fixture.snapshot_parent.iterdir()
                            if path.name.startswith(SNAPSHOT_DIRECTORY_PREFIX)
                        )
                        snapshot = snapshot_directory / "codex"
                        snapshot.unlink()
                        snapshot.write_bytes(b"replacement object")
                        os.chmod(snapshot, 0o600)
                    else:
                        os.fchmod(destination_fd, 0o400)
                    raise RuntimeError(f"injected {mutation} copy failure")

                expected_error = (
                    CodexExecutableError
                    if mutation == "content"
                    else CodexExecutableRetentionRequired
                )
                with self.assertRaises(expected_error) as caught:
                    _authenticate(
                        fixture,
                        FakeRunner(fixture),
                        snapshot_copier=fail_copy,
                    )

                if mutation == "content":
                    self.assertEqual(list(fixture.snapshot_parent.iterdir()), [])
                    continue

                retained = next(
                    resource
                    for resource in caught.exception.retained_resources
                    if isinstance(
                        resource,
                        codex_executable._RetainedNewSnapshot,
                    )
                )
                try:
                    os.fstat(retained.parent_fd)
                    assert retained.directory_fd is not None
                    os.fstat(retained.directory_fd)
                    assert retained.file_fd is not None
                    os.fstat(retained.file_fd)
                    evidence = next(
                        evidence
                        for evidence in caught.exception.recovery_evidence
                        if isinstance(
                            evidence,
                            codex_executable.NewSnapshotRollbackRecoveryEvidence,
                        )
                    )
                    self.assertEqual(
                        evidence.protected_property,
                        (
                            "object-identity"
                            if mutation == "object"
                            else "access-policy"
                        ),
                    )
                    self.assertEqual(
                        evidence.failure_kind,
                        "revalidation-mismatch",
                    )
                    self.assertEqual(evidence.entry_state, "public")
                finally:
                    retained.close_descriptors_for_recovery()

    def test_new_snapshot_rollback_fsync_interrupt_retains_quarantine_name(
        self,
    ) -> None:
        with owned_temporary_directory("codex-new-snapshot-fsync-") as root:
            fixture = _build_fixture(root)
            original_rename = os.rename
            original_fsync = os.fsync
            quarantine_name: str | None = None
            interrupted = False

            def fail_copy(*_arguments: object) -> SnapshotCopyResult:
                raise RuntimeError("injected copy failure")

            def record_rename(
                source: bytes,
                destination: bytes,
                **kwargs: object,
            ) -> None:
                nonlocal quarantine_name
                original_rename(source, destination, **kwargs)
                quarantine_name = os.fsdecode(destination)

            def interrupt_quarantine_fsync(descriptor: int) -> None:
                nonlocal interrupted
                if quarantine_name is not None and not interrupted:
                    interrupted = True
                    raise KeyboardInterrupt(
                        "injected quarantine parent fsync interrupt"
                    )
                original_fsync(descriptor)

            with (
                mock.patch.object(
                    codex_executable.os,
                    "rename",
                    side_effect=record_rename,
                ),
                mock.patch.object(
                    codex_executable.os,
                    "fsync",
                    side_effect=interrupt_quarantine_fsync,
                ),
                self.assertRaises(CodexExecutableRetentionRequired) as caught,
            ):
                _authenticate(
                    fixture,
                    FakeRunner(fixture),
                    snapshot_copier=fail_copy,
                )

            self.assertTrue(interrupted)
            retained = next(
                resource
                for resource in caught.exception.retained_resources
                if isinstance(
                    resource,
                    codex_executable._RetainedNewSnapshot,
                )
            )
            try:
                self.assertEqual(retained.quarantine_name, quarantine_name)
                assert quarantine_name is not None
                self.assertTrue(
                    quarantine_name.startswith(
                        codex_executable.SNAPSHOT_QUARANTINE_PREFIX
                    )
                )
                self.assertTrue((fixture.snapshot_parent / quarantine_name).is_dir())
                self.assertFalse(
                    (fixture.snapshot_parent / retained.public_name).exists()
                )
                os.fstat(retained.parent_fd)
                assert retained.directory_fd is not None
                os.fstat(retained.directory_fd)
                assert retained.file_fd is not None
                os.fstat(retained.file_fd)
                evidence = next(
                    evidence
                    for evidence in caught.exception.recovery_evidence
                    if isinstance(
                        evidence,
                        codex_executable.NewSnapshotRollbackRecoveryEvidence,
                    )
                )
                self.assertEqual(evidence.operation, "quarantine-parent-fsync")
                self.assertEqual(evidence.failure_kind, "durability-unproven")
                self.assertEqual(evidence.protected_property, "durability")
                self.assertEqual(evidence.quarantine_name, quarantine_name)
                self.assertEqual(evidence.entry_state, "quarantined")
            finally:
                retained.close_descriptors_for_recovery()

    def test_new_snapshot_rollback_revalidation_failure_retains_quarantine(
        self,
    ) -> None:
        with owned_temporary_directory("codex-new-snapshot-revalidate-") as root:
            fixture = _build_fixture(root)
            original_rename = os.rename
            original_stat = os.stat
            quarantine_name: str | None = None
            failed = False

            def fail_copy(*_arguments: object) -> SnapshotCopyResult:
                raise RuntimeError("injected copy failure")

            def record_rename(
                source: bytes,
                destination: bytes,
                **kwargs: object,
            ) -> None:
                nonlocal quarantine_name
                original_rename(source, destination, **kwargs)
                quarantine_name = os.fsdecode(destination)

            def fail_quarantine_stat(
                path: object,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                nonlocal failed
                if (
                    quarantine_name is not None
                    and os.fsdecode(path) == quarantine_name
                    and not failed
                ):
                    failed = True
                    raise OSError(
                        errno.EIO,
                        "injected quarantine revalidation failure",
                    )
                return original_stat(path, *args, **kwargs)

            with (
                mock.patch.object(
                    codex_executable.os,
                    "rename",
                    side_effect=record_rename,
                ),
                mock.patch.object(
                    codex_executable.os,
                    "stat",
                    side_effect=fail_quarantine_stat,
                ),
                self.assertRaises(CodexExecutableRetentionRequired) as caught,
            ):
                _authenticate(
                    fixture,
                    FakeRunner(fixture),
                    snapshot_copier=fail_copy,
                )

            self.assertTrue(failed)
            retained = next(
                resource
                for resource in caught.exception.retained_resources
                if isinstance(
                    resource,
                    codex_executable._RetainedNewSnapshot,
                )
            )
            try:
                self.assertEqual(retained.quarantine_name, quarantine_name)
                os.fstat(retained.parent_fd)
                assert retained.directory_fd is not None
                os.fstat(retained.directory_fd)
                assert retained.file_fd is not None
                os.fstat(retained.file_fd)
                evidence = next(
                    evidence
                    for evidence in caught.exception.recovery_evidence
                    if isinstance(
                        evidence,
                        codex_executable.NewSnapshotRollbackRecoveryEvidence,
                    )
                )
                self.assertEqual(
                    evidence.operation,
                    "revalidate-quarantined-directory",
                )
                self.assertEqual(
                    evidence.failure_kind,
                    "revalidation-unavailable",
                )
                self.assertEqual(evidence.protected_property, "availability")
                self.assertEqual(evidence.quarantine_name, quarantine_name)
                self.assertEqual(evidence.entry_state, "quarantined")
            finally:
                retained.close_descriptors_for_recovery()

    def test_new_snapshot_rollback_rename_result_gap_revalidates_entry_state(
        self,
    ) -> None:
        with owned_temporary_directory("codex-new-snapshot-rename-gap-") as root:
            fixture = _build_fixture(root)
            target_offset = _call_result_next_opcode_offset(
                codex_executable._rollback_new_snapshot,
                called_name="rename",
            )
            interruption = KeyboardInterrupt(
                "injected snapshot quarantine rename result interrupt"
            )
            injected = False

            def fail_copy(*_arguments: object) -> SnapshotCopyResult:
                raise RuntimeError("injected copy failure")

            def interrupt_rename_result(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is codex_executable._rollback_new_snapshot.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_rename_result

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_rename_result)
                with self.assertRaises(CodexExecutableRetentionRequired) as caught:
                    _authenticate(
                        fixture,
                        FakeRunner(fixture),
                        snapshot_copier=fail_copy,
                    )
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(injected)
            self.assertIs(caught.exception.__cause__, interruption)
            retained = next(
                resource
                for resource in caught.exception.retained_resources
                if isinstance(resource, codex_executable._RetainedNewSnapshot)
            )
            try:
                self.assertEqual(retained.entry_state, "quarantined")
                self.assertEqual(
                    retained.entry_state_source,
                    "descriptor-bound-revalidation",
                )
                assert retained.quarantine_name is not None
                self.assertFalse(
                    (fixture.snapshot_parent / retained.public_name).exists()
                )
                self.assertTrue(
                    (fixture.snapshot_parent / retained.quarantine_name).is_dir()
                )
                evidence = next(
                    item
                    for item in caught.exception.recovery_evidence
                    if isinstance(
                        item,
                        codex_executable.NewSnapshotRollbackRecoveryEvidence,
                    )
                )
                self.assertEqual(evidence.entry_state, "quarantined")
                self.assertEqual(
                    evidence.entry_state_source,
                    "descriptor-bound-revalidation",
                )
                self.assertEqual(evidence.failure_kind, "durability-unproven")
                self.assertEqual(evidence.protected_property, "durability")
            finally:
                retained.close_descriptors_for_recovery()

    def test_new_snapshot_rollback_rmdir_result_gap_revalidates_entry_state(
        self,
    ) -> None:
        with owned_temporary_directory("codex-new-snapshot-rmdir-gap-") as root:
            fixture = _build_fixture(root)
            target_offset = _call_result_next_opcode_offset(
                codex_executable._rollback_new_snapshot,
                called_name="rmdir",
            )
            interruption = SystemExit("injected snapshot quarantine rmdir result exit")
            injected = False

            def fail_copy(*_arguments: object) -> SnapshotCopyResult:
                raise RuntimeError("injected copy failure")

            def interrupt_rmdir_result(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is codex_executable._rollback_new_snapshot.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_rmdir_result

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_rmdir_result)
                with self.assertRaises(CodexExecutableRetentionRequired) as caught:
                    _authenticate(
                        fixture,
                        FakeRunner(fixture),
                        snapshot_copier=fail_copy,
                    )
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(injected)
            self.assertIs(caught.exception.__cause__, interruption)
            retained = next(
                resource
                for resource in caught.exception.retained_resources
                if isinstance(resource, codex_executable._RetainedNewSnapshot)
            )
            try:
                self.assertEqual(retained.entry_state, "removed-unfsynced")
                self.assertEqual(
                    retained.entry_state_source,
                    "descriptor-bound-revalidation",
                )
                self.assertFalse(
                    (fixture.snapshot_parent / retained.public_name).exists()
                )
                assert retained.quarantine_name is not None
                self.assertFalse(
                    (fixture.snapshot_parent / retained.quarantine_name).exists()
                )
                evidence = next(
                    item
                    for item in caught.exception.recovery_evidence
                    if isinstance(
                        item,
                        codex_executable.NewSnapshotRollbackRecoveryEvidence,
                    )
                )
                self.assertEqual(evidence.entry_state, "removed-unfsynced")
                self.assertEqual(
                    evidence.entry_state_source,
                    "descriptor-bound-revalidation",
                )
                self.assertEqual(evidence.failure_kind, "durability-unproven")
                self.assertEqual(evidence.protected_property, "durability")
            finally:
                retained.close_descriptors_for_recovery()

    def test_generated_schema_cleanup_retains_original_and_replacement_on_race(
        self,
    ) -> None:
        with owned_temporary_directory("codex-schema-cleanup-race-") as root:
            fixture = _build_fixture(root)
            schema_work_root = root / "schema-work"
            schema_work_root.mkdir(mode=0o700)
            replacement_stage = schema_work_root / "replacement-stage"
            replacement_stage.mkdir(mode=0o700)
            replacement_marker = replacement_stage / "replacement.txt"
            replacement_marker.write_text("replacement evidence", encoding="ascii")
            displaced = schema_work_root / "original-evidence"
            original_require = CustodiedManifest.require_live_custody
            swapped = False

            def swap_after_validation(manifest: CustodiedManifest) -> None:
                nonlocal swapped
                original_require(manifest)
                if swapped or manifest.roots[0].label != "generated-schema":
                    return
                swapped = True
                output = schema_work_root / os.fsdecode(manifest.roots[0].name)
                os.rename(output, displaced)
                os.rename(replacement_stage, output)

            with (
                mock.patch.object(
                    CustodiedManifest,
                    "require_live_custody",
                    new=swap_after_validation,
                ),
                self.assertRaisesRegex(
                    CodexExecutableRetentionRequired,
                    "cleanup transaction did not complete",
                ) as caught,
            ):
                _authenticate(
                    fixture,
                    FakeRunner(fixture),
                    aggregate_schema_path=None,
                    schema_work_root=schema_work_root,
                )

            retained_manifests = tuple(
                resource
                for resource in caught.exception.retained_resources
                if isinstance(resource, CustodiedManifest)
            )
            self.assertEqual(len(retained_manifests), 1)
            self.assertEqual(len(retained_manifests[0].root_fds), 1)
            os.fstat(retained_manifests[0].root_fds[0])
            try:
                self.assertTrue(swapped)
                self.assertEqual(
                    (displaced / AGGREGATE_SCHEMA_NAME).read_bytes(),
                    SYNTHETIC_SCHEMA,
                )
                replacement_directories = tuple(
                    path
                    for path in schema_work_root.iterdir()
                    if path.name.startswith(codex_executable.SCHEMA_DIRECTORY_PREFIX)
                )
                self.assertEqual(len(replacement_directories), 1)
                self.assertEqual(
                    (replacement_directories[0] / replacement_marker.name).read_text(
                        encoding="ascii"
                    ),
                    "replacement evidence",
                )
                self.assertTrue(
                    any(
                        path.suffix == ".manifest"
                        for path in schema_work_root.iterdir()
                    )
                )
            finally:
                for resource in caught.exception.retained_resources:
                    if isinstance(resource, codex_executable._StagedSnapshot):
                        codex_executable._close_staged_snapshot_fds(resource)
                    elif isinstance(
                        resource,
                        codex_executable._RetainedGeneratedSchema,
                    ):
                        resource.close_descriptors_for_recovery()
                    elif isinstance(resource, CustodiedManifest):
                        resource.close()

    def test_generated_schema_manifest_call_to_store_interrupt_retains_live_root_fd(
        self,
    ) -> None:
        with owned_temporary_directory("codex-schema-manifest-store-") as root:
            work_root_path = root / "schema-work"
            work_root_path.mkdir(mode=0o700)
            output_name = "codex-schema-interrupted"
            output_path = work_root_path / output_name
            output_path.mkdir(mode=0o700)
            (output_path / AGGREGATE_SCHEMA_NAME).write_bytes(SYNTHETIC_SCHEMA)
            work_root = codex_executable._open_path_anchor(
                work_root_path,
                owner_uid=os.getuid(),
                leaf_kind="directory",
                require_executable=False,
            )
            output_anchor = codex_executable._open_path_anchor(
                output_path,
                owner_uid=os.getuid(),
                leaf_kind="directory",
                require_executable=False,
            )
            target_offset = _call_result_store_offset(
                codex_executable._destroy_generated_schema_directory,
                called_name="build_custodied_manifest",
                stored_name="manifest",
            )
            interruption = KeyboardInterrupt(
                "injected generated-schema manifest CALL-to-STORE interrupt"
            )
            injected = False

            def interrupt_result_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is codex_executable._destroy_generated_schema_directory.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_result_store

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_result_store)
                with self.assertRaises(CodexExecutableRetentionRequired) as caught:
                    codex_executable._destroy_generated_schema_directory(
                        work_root=work_root,
                        output_anchor=output_anchor,
                        output_name=output_name,
                    )
            finally:
                sys.settrace(previous_trace)

            retained_manifests = tuple(
                resource
                for resource in caught.exception.retained_resources
                if isinstance(resource, CustodiedManifest)
            )
            try:
                self.assertTrue(injected)
                self.assertIs(caught.exception.__cause__, interruption)
                self.assertEqual(len(retained_manifests), 1)
                self.assertEqual(len(retained_manifests[0].root_fds), 1)
                os.fstat(retained_manifests[0].root_fds[0])
                self.assertTrue(output_path.is_dir())
            finally:
                for manifest in retained_manifests:
                    manifest.close()
                os.close(output_anchor.fd)
                os.close(work_root.fd)

    def test_generated_schema_delete_result_interrupt_retains_completion_proof(
        self,
    ) -> None:
        with owned_temporary_directory("codex-schema-delete-store-") as root:
            work_root_path = root / "schema-work"
            work_root_path.mkdir(mode=0o700)
            output_name = "codex-schema-deleted"
            output_path = work_root_path / output_name
            output_path.mkdir(mode=0o700)
            (output_path / AGGREGATE_SCHEMA_NAME).write_bytes(SYNTHETIC_SCHEMA)
            work_root = codex_executable._open_path_anchor(
                work_root_path,
                owner_uid=os.getuid(),
                leaf_kind="directory",
                require_executable=False,
            )
            output_anchor = codex_executable._open_path_anchor(
                output_path,
                owner_uid=os.getuid(),
                leaf_kind="directory",
                require_executable=False,
            )
            target_offset = _call_result_store_offset(
                codex_executable._destroy_generated_schema_directory,
                called_name="delete_custodied_roots",
                stored_name="deletion_proof",
            )
            interruption = KeyboardInterrupt(
                "injected generated-schema deletion CALL-to-STORE interrupt"
            )
            injected = False

            def interrupt_result_store(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is codex_executable._destroy_generated_schema_directory.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_result_store

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_result_store)
                with self.assertRaises(CodexExecutableRetentionRequired) as caught:
                    codex_executable._destroy_generated_schema_directory(
                        work_root=work_root,
                        output_anchor=output_anchor,
                        output_name=output_name,
                    )
            finally:
                sys.settrace(previous_trace)

            retained_manifests = tuple(
                resource
                for resource in caught.exception.retained_resources
                if isinstance(resource, CustodiedManifest)
            )
            try:
                self.assertTrue(injected)
                self.assertIs(caught.exception.__cause__, interruption)
                self.assertFalse(output_path.exists())
                self.assertNotIn("schema trees were retained", str(caught.exception))
                proof = caught.exception.completed_deletion_proof
                self.assertTrue(proof["parent_fsync_complete"])
                self.assertTrue(proof["exact_names_absent"])
                evidence = next(
                    item
                    for item in caught.exception.recovery_evidence
                    if isinstance(
                        item,
                        codex_executable.GeneratedSchemaDeletionRecoveryEvidence,
                    )
                )
                self.assertEqual(evidence.stage, "generated-schema-deletion-complete")
                self.assertEqual(evidence.manifest_sha256, proof["manifest_sha256"])
                self.assertEqual(len(retained_manifests), 1)
            finally:
                for retained_manifest in retained_manifests:
                    retained_manifest.close()
                os.close(output_anchor.fd)
                os.close(work_root.fd)

    def _assert_generated_schema_retention_interrupt(
        self,
        *,
        after_retention_store: bool,
    ) -> None:
        with owned_temporary_directory("codex-schema-retain-window-") as root:
            work_root_path = root / "schema-work"
            work_root_path.mkdir(mode=0o700)
            output_name = "codex-schema-retained"
            output_path = work_root_path / output_name
            output_path.mkdir(mode=0o700)
            (output_path / AGGREGATE_SCHEMA_NAME).write_bytes(SYNTHETIC_SCHEMA)
            work_root = codex_executable._open_path_anchor(
                work_root_path,
                owner_uid=os.getuid(),
                leaf_kind="directory",
                require_executable=False,
            )
            output_anchor = codex_executable._open_path_anchor(
                output_path,
                owner_uid=os.getuid(),
                leaf_kind="directory",
                require_executable=False,
            )
            retention_store = _call_result_store_offset(
                codex_executable._destroy_generated_schema_directory,
                called_name="retain",
                stored_name="retained_manifest",
            )
            target_offset = (
                _instruction_after_offset(
                    codex_executable._destroy_generated_schema_directory,
                    retention_store,
                )
                if after_retention_store
                else retention_store
            )
            interruption = KeyboardInterrupt(
                "injected generated-schema manifest retention interrupt"
            )
            original = RuntimeError("synthetic generated-schema cleanup failure")
            original_evidence: list[QuarantinedRootRecoveryEvidence] = []
            injected = False

            def fail_delete(
                manifest: CustodiedManifest,
                *,
                deadline: float,
                result_owner: object,
            ) -> None:
                del deadline, result_owner
                evidence = QuarantinedRootRecoveryEvidence(
                    label="generated-schema",
                    stage="recursive-delete",
                    parent_fd=work_root.fd,
                    root_fd=manifest.root_fds[0],
                    original_name=os.fsencode(output_name),
                    quarantine_name=(b".targeted-cleanup-quarantine-" + b"a" * 32),
                    parent_identity=codex_executable._cleanup_identity(
                        work_root.identity
                    ),
                    expected_identity=codex_executable._cleanup_identity(
                        output_anchor.identity
                    ),
                )
                original_evidence.append(evidence)
                recovery_cleanup._attach_quarantined_root_recovery(
                    original,
                    evidence,
                )
                raise original

            def interrupt_retention(
                frame: object,
                event: str,
                _argument: object,
            ) -> object:
                nonlocal injected
                if (
                    getattr(frame, "f_code", None)
                    is codex_executable._destroy_generated_schema_directory.__code__
                ):
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not injected
                        and event == "opcode"
                        and getattr(frame, "f_lasti", None) == target_offset
                    ):
                        injected = True
                        raise interruption
                return interrupt_retention

            previous_trace = sys.gettrace()
            try:
                with mock.patch.object(
                    codex_executable,
                    "delete_custodied_roots",
                    side_effect=fail_delete,
                ):
                    sys.settrace(interrupt_retention)
                    with self.assertRaises(CodexExecutableRetentionRequired) as caught:
                        codex_executable._destroy_generated_schema_directory(
                            work_root=work_root,
                            output_anchor=output_anchor,
                            output_name=output_name,
                        )
            finally:
                sys.settrace(previous_trace)

            retained_manifests = tuple(
                resource
                for resource in caught.exception.retained_resources
                if isinstance(resource, CustodiedManifest)
            )
            try:
                self.assertTrue(injected)
                self.assertIs(caught.exception.__cause__, original)
                self.assertIs(caught.exception.source_cleanup_error, original)
                self.assertEqual(
                    caught.exception.retention_publication_errors,
                    (interruption,),
                )
                self.assertEqual(len(retained_manifests), 1)
                self.assertEqual(len(retained_manifests[0].root_fds), 1)
                os.fstat(retained_manifests[0].root_fds[0])
                self.assertEqual(len(original_evidence), 1)
                self.assertIn(
                    original_evidence[0],
                    caught.exception.recovery_evidence,
                )
                self.assertEqual(
                    recovery_cleanup.quarantined_root_recovery_evidence(
                        caught.exception
                    ),
                    tuple(original_evidence),
                )
                self.assertTrue(output_path.is_dir())
            finally:
                for retained_manifest in retained_manifests:
                    retained_manifest.close()
                os.close(output_anchor.fd)
                os.close(work_root.fd)

    def test_generated_schema_retain_call_to_store_interrupt_keeps_manifest_fd(
        self,
    ) -> None:
        self._assert_generated_schema_retention_interrupt(
            after_retention_store=False,
        )

    def test_generated_schema_post_retention_interrupt_keeps_original_evidence(
        self,
    ) -> None:
        self._assert_generated_schema_retention_interrupt(
            after_retention_store=True,
        )


class CodexExecutableCustodyTests(unittest.TestCase):
    def test_cleanup_failure_retains_snapshot_custody_and_recovery_evidence(
        self,
    ) -> None:
        with owned_temporary_directory("codex-cleanup-retain-") as root:
            fixture = _build_fixture(root)
            custody = _authenticate(fixture, FakeRunner(fixture))
            snapshot_path = custody.snapshot_path
            directory_fd = custody.directory_fd
            executable_fd = custody.executable_fd
            custody.confirm_process_quiescence(_quiescence())
            with (
                mock.patch.object(
                    codex_executable,
                    "_destroy_staged_snapshot",
                    side_effect=OSError(errno.EIO, "injected cleanup refusal"),
                ),
                self.assertRaises(CodexExecutableRetentionRequired) as caught,
            ):
                custody.cleanup()

            try:
                self.assertTrue(custody.closed)
                self.assertTrue(custody.retained_snapshot)
                self.assertTrue(snapshot_path.is_file())
                os.fstat(directory_fd)
                os.fstat(executable_fd)
                self.assertIn(custody, caught.exception.retained_resources)
                evidence = next(
                    evidence
                    for evidence in caught.exception.recovery_evidence
                    if evidence.stage == "snapshot-cleanup"
                )
                self.assertEqual(evidence.directory_fd, directory_fd)
                self.assertEqual(evidence.executable_fd, executable_fd)
            finally:
                codex_executable._close_staged_snapshot_fds(custody._staged)

    def test_owner_snapshot_attestation_requires_fresh_authenticated_phase(
        self,
    ) -> None:
        with owned_temporary_directory("codex-attestation-phase-") as root:
            fixture = _build_fixture(root)
            custody = _authenticate(fixture, FakeRunner(fixture))
            handoff = custody.pre_fork_revalidate()
            with self.assertRaisesRegex(
                CodexExecutableCustodyStale,
                "requires fresh authenticated custody",
            ):
                custody.attest_owner_snapshot_launch()
            custody.confirm_process_quiescence(_quiescence(handoff_token=handoff.token))
            custody.cleanup()

    def test_complete_handoff_uses_snapshot_and_records_self_mutation_denial(
        self,
    ) -> None:
        with owned_temporary_directory("codex-handoff-") as root:
            fixture = _build_fixture(root)
            protection_verifier = RecordingProtectionVerifier()
            quiescence_verifier = RecordingQuiescenceVerifier()
            custody = _authenticate(
                fixture,
                FakeRunner(fixture),
                snapshot_protection_verifier=protection_verifier,
                quiescence_verifier=quiescence_verifier,
            )
            snapshot_path = custody.snapshot_path
            pre_fork = custody.pre_fork_revalidate()
            protection = _protection(custody)
            target = custody.child_revalidate_immediately_before_exec(
                pre_fork,
                protection=protection,
            )
            self.assertEqual(target.executable_path, str(snapshot_path))
            self.assertNotEqual(target.executable_path, str(fixture.source))
            self.assertIn("deny file-write*", target.seatbelt_rules)
            self.assertEqual(
                protection.denied_operations,
                (
                    "filesystem-write-default",
                    "write",
                    "unlink",
                    "rename",
                    "chmod",
                    "ancestor-relocation",
                    "hardlink-alias",
                    "firmlink-alias",
                ),
            )
            self.assertTrue(protection.self_mutation_probe_denied)
            parent = custody.parent_revalidate_after_exec_handoff(
                target,
                process_id=4242,
            )
            self.assertEqual(parent.phase, "parent-post-exec-handoff")
            self.assertEqual(parent.token, pre_fork.token)
            self.assertEqual(len(protection_verifier.calls), 2)
            _cleanup(
                custody,
                handoff_token=parent.token,
                process_id=4242,
            )
            self.assertEqual(len(quiescence_verifier.calls), 1)
            self.assertFalse(snapshot_path.parent.exists())

    def test_missing_or_false_self_mutation_denial_fails_closed(self) -> None:
        cases = (
            {"denied_operations": ("write", "unlink", "rename")},
            {"self_mutation_probe_denied": False},
            {"no_child_profile_verified": False},
            {"applied_before_snapshot_exec": False},
        )
        for index, changes in enumerate(cases):
            with self.subTest(changes=changes):
                with owned_temporary_directory(f"codex-protection-{index}-") as root:
                    fixture = _build_fixture(root)
                    custody = _authenticate(fixture, FakeRunner(fixture))
                    handoff = custody.pre_fork_revalidate()
                    bad = replace(_protection(custody), **changes)
                    with self.assertRaisesRegex(
                        CodexExecutableCustodyStale,
                        "protection is incomplete",
                    ):
                        custody.child_revalidate_immediately_before_exec(
                            handoff,
                            protection=bad,
                        )
                    custody.confirm_process_quiescence(
                        _quiescence(handoff_token=handoff.token)
                    )
                    custody.cleanup()

    def test_launch_fails_closed_without_protection_verifier(self) -> None:
        with owned_temporary_directory("codex-no-protection-verifier-") as root:
            fixture = _build_fixture(root)
            custody = _authenticate(
                fixture,
                FakeRunner(fixture),
                snapshot_protection_verifier=None,
            )
            handoff = custody.pre_fork_revalidate()
            with self.assertRaisesRegex(
                CodexExecutableCustodyStale,
                "protection verifier is required",
            ):
                custody.child_revalidate_immediately_before_exec(
                    handoff,
                    protection=_protection(custody),
                )
            custody.confirm_process_quiescence(_quiescence(handoff_token=handoff.token))
            custody.cleanup()

    def test_prelaunch_phases_reject_unbound_pid_quiescence(self) -> None:
        for phase in ("authenticated", "pre-fork", "child-before-exec"):
            with self.subTest(phase=phase):
                with owned_temporary_directory(
                    f"codex-unbound-quiescence-{phase}-"
                ) as root:
                    fixture = _build_fixture(root)
                    custody = _authenticate(fixture, FakeRunner(fixture))
                    handoff_token = None
                    if phase != "authenticated":
                        handoff = custody.pre_fork_revalidate()
                        handoff_token = handoff.token
                    if phase == "child-before-exec":
                        custody.child_revalidate_immediately_before_exec(
                            handoff,
                            protection=_protection(custody),
                        )

                    with self.assertRaisesRegex(
                        CodexExecutableCustodyStale,
                        "lacks a bound launch identity",
                    ):
                        custody.confirm_process_quiescence(
                            _quiescence(
                                handoff_token=handoff_token,
                                process_id=99999,
                            )
                        )

                    custody.confirm_process_quiescence(
                        _quiescence(
                            handoff_token=handoff_token,
                            launch_state="never-launched-abort",
                        )
                    )
                    custody.cleanup()

    def test_quiescence_requires_explicit_never_launched_abort_state(self) -> None:
        with owned_temporary_directory("codex-explicit-abort-") as root:
            fixture = _build_fixture(root)
            custody = _authenticate(fixture, FakeRunner(fixture))
            with self.assertRaisesRegex(
                CodexExecutableCustodyStale,
                "lacks a bound launch identity",
            ):
                custody.confirm_process_quiescence(
                    _quiescence(launch_state="bound-launch")
                )
            custody.confirm_process_quiescence(
                _quiescence(launch_state="never-launched-abort")
            )
            custody.cleanup()

    def test_bound_launch_quiescence_requires_the_exact_pid(self) -> None:
        with owned_temporary_directory("codex-bound-quiescence-") as root:
            fixture = _build_fixture(root)
            custody = _authenticate(fixture, FakeRunner(fixture))
            handoff = custody.pre_fork_revalidate()
            target = custody.child_revalidate_immediately_before_exec(
                handoff,
                protection=_protection(custody),
            )
            parent = custody.parent_revalidate_after_exec_handoff(
                target,
                process_id=4242,
            )
            with self.assertRaisesRegex(
                CodexExecutableCustodyStale,
                "PID does not match",
            ):
                custody.confirm_process_quiescence(
                    _quiescence(
                        handoff_token=parent.token,
                        process_id=4343,
                    )
                )
            custody.confirm_process_quiescence(
                _quiescence(
                    handoff_token=parent.token,
                    process_id=4242,
                )
            )
            custody.cleanup()

    def test_path_replacement_is_rejected_at_every_handoff(self) -> None:
        for phase in ("pre-fork", "child-before-exec", "parent-post-exec"):
            with self.subTest(phase=phase):
                with owned_temporary_directory(f"codex-{phase}-race-") as root:
                    fixture = _build_fixture(root)
                    custody = _authenticate(fixture, FakeRunner(fixture))
                    handoff = None
                    process_id = None
                    if phase != "pre-fork":
                        handoff = custody.pre_fork_revalidate()
                    if phase == "parent-post-exec":
                        assert handoff is not None
                        target = custody.child_revalidate_immediately_before_exec(
                            handoff,
                            protection=_protection(custody),
                        )
                        process_id = 4343
                    _replace_snapshot_path(custody)
                    if phase == "pre-fork":
                        with self.assertRaises(CodexExecutableCustodyStale):
                            custody.pre_fork_revalidate()
                    elif phase == "child-before-exec":
                        assert handoff is not None
                        with self.assertRaises(CodexExecutableCustodyStale):
                            custody.child_revalidate_immediately_before_exec(
                                handoff,
                                protection=_protection(custody),
                            )
                    else:
                        with self.assertRaises(CodexExecutableCustodyStale):
                            custody.parent_revalidate_after_exec_handoff(
                                target,
                                process_id=process_id,
                            )
                    custody.confirm_process_quiescence(
                        _quiescence(
                            handoff_token=(handoff.token if handoff else None),
                            process_id=process_id,
                        )
                    )
                    try:
                        with self.assertRaisesRegex(
                            CodexExecutableRetentionRequired,
                            "custody descriptors and suspicious paths were retained",
                        ):
                            custody.cleanup()
                        self.assertTrue(custody.closed)
                        self.assertTrue(custody.retained_snapshot)
                    finally:
                        codex_executable._close_staged_snapshot_fds(custody._staged)

    def test_disappearance_hardlink_and_parent_mode_change_are_rejected(self) -> None:
        mutations = ("disappear", "hardlink", "parent-mode")
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                owned_temporary_directory(f"codex-{mutation}-") as root,
                contextlib.ExitStack() as fixture_cleanup,
            ):
                fixture = _build_fixture(root)
                custody = _authenticate(fixture, FakeRunner(fixture))
                snapshot_path = custody.snapshot_path
                if mutation == "disappear":
                    snapshot_path.unlink()
                elif mutation == "hardlink":
                    hardlink_parent_fd = os.open(
                        snapshot_path.parent,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    )
                    fixture_cleanup.callback(os.close, hardlink_parent_fd)
                    os.link(
                        os.fsencode(snapshot_path.name),
                        b"codex-link",
                        src_dir_fd=hardlink_parent_fd,
                        dst_dir_fd=hardlink_parent_fd,
                        follow_symlinks=False,
                    )
                    hardlink_object = _test_entry_object_identity(
                        os.stat(
                            b"codex-link",
                            dir_fd=hardlink_parent_fd,
                            follow_symlinks=False,
                        )
                    )
                    fixture_cleanup.callback(
                        _remove_exact_test_entry,
                        hardlink_parent_fd,
                        b"codex-link",
                        hardlink_object,
                    )
                else:
                    os.chmod(fixture.snapshot_parent, 0o750)
                with self.assertRaises(CodexExecutableCustodyStale):
                    custody.pre_fork_revalidate()
                if mutation == "parent-mode":
                    os.chmod(fixture.snapshot_parent, 0o700)
                custody.confirm_process_quiescence(_quiescence())
                if mutation == "parent-mode":
                    custody.cleanup()
                else:
                    try:
                        with self.assertRaises(CodexExecutableRetentionRequired):
                            custody.cleanup()
                    finally:
                        codex_executable._close_staged_snapshot_fds(custody._staged)

    def test_stale_handoff_token_is_rejected(self) -> None:
        with owned_temporary_directory("codex-stale-token-") as root:
            fixture = _build_fixture(root)
            custody = _authenticate(fixture, FakeRunner(fixture))
            handoff = custody.pre_fork_revalidate()
            stale = replace(handoff, token="0" * 64)
            with self.assertRaisesRegex(
                CodexExecutableCustodyStale,
                "stale or inconsistent",
            ):
                custody.child_revalidate_immediately_before_exec(
                    stale,
                    protection=_protection(custody),
                )
            custody.confirm_process_quiescence(_quiescence(handoff_token=handoff.token))
            custody.cleanup()

    def test_cleanup_before_quiescence_is_rejected_then_succeeds(self) -> None:
        with owned_temporary_directory("codex-cleanup-quiescence-") as root:
            fixture = _build_fixture(root)
            custody = _authenticate(fixture, FakeRunner(fixture))
            snapshot_path = custody.snapshot_path
            with self.assertRaisesRegex(
                CodexExecutableCustodyStale,
                "requires verified process quiescence",
            ):
                custody.cleanup()
            self.assertTrue(snapshot_path.exists())
            _cleanup(custody)
            self.assertFalse(snapshot_path.parent.exists())

    def test_cleanup_fails_closed_without_quiescence_verifier(self) -> None:
        with owned_temporary_directory("codex-no-quiescence-verifier-") as root:
            fixture = _build_fixture(root)
            custody = _authenticate(
                fixture,
                FakeRunner(fixture),
                quiescence_verifier=None,
            )
            with self.assertRaisesRegex(
                CodexExecutableCustodyStale,
                "quiescence verifier is required",
            ):
                custody.confirm_process_quiescence(_quiescence())
            custody._quiescence_verifier = RecordingQuiescenceVerifier()
            _cleanup(custody)

    def test_fd_bound_exec_api_remains_explicitly_unsupported(self) -> None:
        with owned_temporary_directory("codex-fd-unsupported-") as root:
            fixture = _build_fixture(root)
            custody = _authenticate(fixture, FakeRunner(fixture))
            try:
                revalidated = custody.revalidate()
                self.assertEqual(revalidated.sha256, fixture.policy.expected_sha256)
                with self.assertRaises(CodexExecutableExecutionUnsupported) as raised:
                    custody.revalidate_before_exec()
                self.assertEqual(
                    raised.exception.failure.code,
                    "codex-fd-exec-unsupported",
                )
                self.assertIn(
                    "not accepted as fd-bound execution", str(raised.exception)
                )
                self.assertNotIn("/dev/fd/", str(raised.exception))
            finally:
                _cleanup(custody)

    def test_closed_custody_cannot_be_revalidated(self) -> None:
        with owned_temporary_directory("codex-closed-") as root:
            fixture = _build_fixture(root)
            custody = _authenticate(fixture, FakeRunner(fixture))
            _cleanup(custody)
            custody.cleanup()
            with self.assertRaisesRegex(CodexExecutableError, "custody is closed"):
                custody.revalidate()


if __name__ == "__main__":
    unittest.main()
