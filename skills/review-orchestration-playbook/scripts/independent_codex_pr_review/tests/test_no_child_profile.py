from __future__ import annotations

import contextlib
import dis
import errno
import hashlib
import io
import json
import os
import pathlib
import platform
import resource
import signal
import shutil
import stat
import subprocess
import sys
import threading
import unittest
from collections.abc import Callable
from dataclasses import replace
from unittest import mock

from review_supervisor.codex_executable import (
    ExecutableRevalidationEvidence,
    ExtendedMetadataEvidence,
    FdExecutionEvidence,
    NodeIdentity,
    OperationIdentityEvidence,
    OwnerSnapshotLaunchAttestation,
    PathComponentEvidence,
    SnapshotCopyEvidence,
    SnapshotEvidence,
    build_snapshot_seatbelt_policy,
)
from review_supervisor import no_child_profile as profile
from tests.support import owned_temporary_directory


REQUIRE_LIVE_NO_CHILD_PROFILE_ENV = "CODEX_REVIEW_REQUIRE_LIVE_NO_CHILD_PROFILE"
GITHUB_HOSTED_LEGACY_RUNTIME_PROFILE = "github-macos-26-arm64-26.4-25E246"
GITHUB_HOSTED_LEGACY_RUNTIME_PIN = profile.RuntimePin(
    macos_product_version="26.4",
    macos_build_version="25E246",
    darwin_release="25.4.0",
    sandbox_exec_sha256=(
        "d1ee30dbde955aaa75c7f801fdfea4df05b10129454d7982eb6453f771436d42"
    ),
)
GITHUB_HOSTED_RUNTIME_PINS = {
    GITHUB_HOSTED_LEGACY_RUNTIME_PROFILE: GITHUB_HOSTED_LEGACY_RUNTIME_PIN,
    "github-macos-26-arm64-26.5.2-25F84": profile.RuntimePin(
        macos_product_version="26.5.2",
        macos_build_version="25F84",
        darwin_release="25.5.0",
        sandbox_exec_sha256=(
            "8290e4be7387a0df83cd1559e86afd880464f269450573d012795761fe298f16"
        ),
    ),
}


class _SyntheticProbeProcess:
    def __init__(
        self,
        *,
        pid: int,
        communicate_error: BaseException,
        wait_error: BaseException | None = None,
    ) -> None:
        self.pid = pid
        self.returncode: int | None = None
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()
        self.communicate_error = communicate_error
        self.wait_error = wait_error
        self.wait_calls = 0

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls += 1
        if self.wait_error is not None:
            raise self.wait_error
        self.returncode = -signal.SIGKILL
        return self.returncode

    def communicate(
        self,
        input: bytes | None = None,
        timeout: float | None = None,
    ) -> tuple[bytes, bytes]:
        raise self.communicate_error


class _InterruptingLaunchResultOwner:
    def __init__(self) -> None:
        self.launched: profile.LaunchedNoChildProcess | None = None
        self.owns_calls = 0

    def publish(self, launched: profile.LaunchedNoChildProcess) -> None:
        self.launched = launched

    def owns(self, launched: profile.LaunchedNoChildProcess) -> bool:
        self.owns_calls += 1
        self_identity_matches = self.launched is launched
        raise KeyboardInterrupt(
            "injected result-owner ownership query "
            f"{self.owns_calls}; identity_matches={self_identity_matches}"
        )


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _path_evidence(
    path: pathlib.Path,
    *,
    leaf_kind: str,
) -> tuple[PathComponentEvidence, ...]:
    current = pathlib.Path("/")
    evidence = [
        PathComponentEvidence(
            path="/",
            kind="directory",
            identity=NodeIdentity.from_stat(os.stat("/", follow_symlinks=False)),
        )
    ]
    parts = path.parts[1:]
    for index, component in enumerate(parts):
        current /= component
        evidence.append(
            PathComponentEvidence(
                path=str(current),
                kind=leaf_kind if index == len(parts) - 1 else "directory",
                identity=NodeIdentity.from_stat(
                    os.stat(current, follow_symlinks=False)
                ),
            )
        )
    return tuple(evidence)


def _build_owner_snapshot_attestation(
    root: pathlib.Path,
    *,
    source: pathlib.Path,
) -> OwnerSnapshotLaunchAttestation:
    snapshot_parent = root / "snapshot-parent"
    snapshot_directory = snapshot_parent / "private-snapshot"
    snapshot_directory.mkdir(parents=True, mode=0o700)
    os.chmod(snapshot_parent, 0o700)
    os.chmod(snapshot_directory, 0o700)
    snapshot_path = snapshot_directory / "codex"
    shutil.copyfile(source, snapshot_path)
    os.chmod(snapshot_path, 0o500)
    directory_fd = os.open(
        snapshot_directory,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    executable_fd = os.open(
        snapshot_path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    directory_identity = NodeIdentity.from_stat(os.fstat(directory_fd))
    executable_identity = NodeIdentity.from_stat(os.fstat(executable_fd))
    expected_sha256 = _sha256(snapshot_path)
    operation = OperationIdentityEvidence(
        operation="test-owner-snapshot-revalidation",
        before=executable_identity,
        after=executable_identity,
    )
    fd_execution = FdExecutionEvidence(
        supported=False,
        mechanism="unsupported-on-macos",
        reason="synthetic custody attestation for no-child tests",
    )
    clear_metadata = ExtendedMetadataEvidence(0, (), False)
    snapshot = SnapshotEvidence(
        parent_path=str(snapshot_parent),
        parent_identity=NodeIdentity.from_stat(
            os.stat(snapshot_parent, follow_symlinks=False)
        ),
        parent_components=_path_evidence(
            snapshot_parent,
            leaf_kind="directory",
        ),
        directory_path=str(snapshot_directory),
        executable_path=str(snapshot_path),
        directory_identity=directory_identity,
        executable_identity=executable_identity,
        directory_components=_path_evidence(
            snapshot_directory,
            leaf_kind="directory",
        ),
        executable_components=_path_evidence(
            snapshot_path,
            leaf_kind="file",
        ),
        directory_metadata=clear_metadata,
        executable_metadata=clear_metadata,
        copy=SnapshotCopyEvidence(
            source_identity_before=executable_identity,
            source_identity_after=executable_identity,
            destination_identity=executable_identity,
            size=executable_identity.size,
            sha256=expected_sha256,
            max_bytes=executable_identity.size,
            source_fd_only=True,
            file_fsynced=True,
            directory_fsynced=True,
        ),
        seatbelt_policy=build_snapshot_seatbelt_policy(snapshot_directory),
    )
    return OwnerSnapshotLaunchAttestation(
        executable_fd=executable_fd,
        directory_fd=directory_fd,
        snapshot=snapshot,
        expected_sha256=expected_sha256,
        revalidation=ExecutableRevalidationEvidence(
            identity=executable_identity,
            sha256=expected_sha256,
            operation=operation,
            fd_execution=fd_execution,
        ),
    )


def _close_owner_snapshot_attestation(
    attestation: OwnerSnapshotLaunchAttestation,
) -> None:
    os.close(attestation.executable_fd)
    os.close(attestation.directory_fd)


def _synthetic_probe_identities() -> tuple[
    profile.ExecutableIdentity, profile.ExecutableIdentity
]:
    probe = profile.ExecutableIdentity(
        path="/synthetic/python3.13",
        device=1,
        inode=2,
        mode=stat.S_IFREG | 0o555,
        uid=0,
        gid=0,
        size=4,
        mtime_ns=1,
        ctime_ns=1,
        sha256="a" * 64,
    )
    return (
        probe,
        replace(
            probe,
            path="/synthetic/true",
            inode=3,
            sha256="b" * 64,
        ),
    )


def _synthetic_probe_attestation(
    executable: profile.ExecutableIdentity,
) -> profile.PathExecutedExecutableAttestation:
    return profile.PathExecutedExecutableAttestation(
        executable=executable,
        components=(),
    )


def _publish_synthetic_probe_process(
    process: _SyntheticProbeProcess,
) -> Callable[..., _SyntheticProbeProcess]:
    def spawn(
        owner: profile._ProbePopenOwner,
        *_args: object,
        **_kwargs: object,
    ) -> _SyntheticProbeProcess:
        owner.process = process
        owner.ownership_published = True
        owner.popen_call_started = True
        owner.popen_call_completed = True
        return process

    return spawn


def _publish_synthetic_launch_receipt(
    *,
    pid: int,
    error_read: int,
    error_write: int,
) -> Callable[[profile._NoChildLaunchReceiptOwner], tuple[int, int, int]]:
    def fork(
        owner: profile._NoChildLaunchReceiptOwner,
    ) -> tuple[int, int, int]:
        receipt = profile._NoChildLaunchReceipt(
            creator_pid=os.getpid(),
            error_read_fd=error_read,
            error_write_fd=error_write,
            fork_call_started=True,
            fork_call_completed=True,
            returned_pid=pid,
            leader_pid=pid,
            leader_receipt_received=True,
        )
        owner.publish(receipt)
        return pid, error_read, error_write

    return fork


def _publish_synthetic_pipe_receipt(
    *,
    error_read: int,
    error_write: int,
) -> Callable[
    [profile._NoChildLaunchReceiptOwner],
    profile._NoChildLaunchReceipt,
]:
    def open_pipe(
        owner: profile._NoChildLaunchReceiptOwner,
    ) -> profile._NoChildLaunchReceipt:
        receipt = profile._NoChildLaunchReceipt(
            creator_pid=os.getpid(),
            error_read_fd=error_read,
            error_write_fd=error_write,
            pipe_call_started=True,
            pipe_call_completed=True,
        )
        owner.publish(receipt)
        return receipt

    return open_pipe


def _hold_synthetic_launch_child(*_args: object, **_kwargs: object) -> None:
    os.setsid()
    while True:
        signal.pause()


def _synthetic_prepared_launch() -> profile.PreparedNoChildProfile:
    executable = profile.ExecutableIdentity(
        path="/synthetic/app-server",
        device=1,
        inode=2,
        mode=stat.S_IFREG | 0o555,
        uid=os.getuid(),
        gid=os.getgid(),
        size=4,
        mtime_ns=1,
        ctime_ns=1,
        sha256="a" * 64,
    )
    return profile.PreparedNoChildProfile(
        executable=executable,
        expected_sha256=executable.sha256,
        seatbelt_profile="(version 1)\n",
        evidence=mock.sentinel.compatibility,
    )


def _call_followup_offset(
    function: Callable[..., object],
    *,
    called_name: str,
    following_opname: str,
    following_argval: object | None = None,
) -> int:
    instructions = list(dis.get_instructions(function))
    matches: list[int] = []
    for index, instruction in enumerate(instructions):
        if instruction.argval != called_name:
            continue
        for candidate_index in range(index + 1, len(instructions) - 1):
            if not instructions[candidate_index].opname.startswith("CALL"):
                continue
            following = instructions[candidate_index + 1]
            if following.opname == following_opname and (
                following_argval is None or following.argval == following_argval
            ):
                matches.append(following.offset)
            break
    if len(matches) != 1:
        raise AssertionError(
            f"expected one {called_name} CALL->{following_opname}, got {matches}"
        )
    return matches[0]


def _successful_preexec_state(pid: int) -> bytes:
    return json.dumps(
        {
            "ok": True,
            "setsid_succeeded": True,
            "pid": pid,
            "process_group": pid,
            "session_id": pid,
            "nproc_soft": 1,
            "nproc_hard": 1,
            "error_number": None,
            "detail": "",
        },
        sort_keys=True,
    ).encode("ascii")


def _write_synthetic_macho(path: pathlib.Path, *, alternate: bool = False) -> None:
    path.write_bytes(b"\xca\xfe\xba\xbe" if alternate else b"\xcf\xfa\xed\xfe")
    path.chmod(0o755)


_SECURE_PROFILE_WORKER = r"""
import errno
import json
import os
import socket
import sys
import time

writable_root = sys.argv[1]
outside_path = sys.argv[2]
firmlink_snapshot = sys.argv[3]
result = {}

with open(os.path.join(writable_root, "allowed.json"), "w", encoding="ascii") as handle:
    handle.write("allowed\n")
result["writable_root"] = True

try:
    with open(outside_path, "w", encoding="ascii") as handle:
        handle.write("forbidden\n")
except OSError as error:
    result["outside_write_denied"] = error.errno in {errno.EACCES, errno.EPERM}
else:
    result["outside_write_denied"] = False

try:
    os.chmod(firmlink_snapshot, 0o700)
except OSError as error:
    result["firmlink_write_denied"] = error.errno in {errno.EACCES, errno.EPERM}
else:
    result["firmlink_write_denied"] = False

network = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    network.bind(("127.0.0.1", 0))
    result["network"] = True
finally:
    network.close()

try:
    os.execve("/usr/bin/true", ["/usr/bin/true"], {})
except OSError as error:
    result["alternate_exec_denied"] = error.errno == errno.EPERM
else:
    result["alternate_exec_denied"] = False

print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
time.sleep(0.5)
"""


def _synthetic_compatible_observations(
    *,
    profile_sha256: str,
    parent_limit: tuple[int, int],
) -> list[profile.ProbeObservation]:
    observations: list[profile.ProbeObservation] = []
    actions = (
        "baseline",
        "fork",
        "posix_spawn",
        "popen",
        "double_fork",
        "setsid",
        "setpgid",
        "exec",
    )
    for layer_index, layer in enumerate(("rlimit", "seatbelt", "combined")):
        limit = parent_limit if layer == "seatbelt" else (0, 0)
        layer_profile = None if layer == "rlimit" else profile_sha256
        for action_index, action in enumerate(actions):
            pid = 1000 + layer_index * 100 + action_index
            if action == "baseline":
                outcome = "observed"
                error_number = None
            elif layer == "rlimit" and action == "exec":
                outcome = "allowed"
                error_number = None
            else:
                outcome = "denied"
                error_number = (
                    errno.EAGAIN
                    if action in {"fork", "posix_spawn", "popen", "double_fork"}
                    and layer in {"rlimit", "combined"}
                    else errno.EPERM
                )
            observations.append(
                profile.ProbeObservation(
                    layer=layer,
                    action=action,
                    outcome=outcome,
                    error_number=error_number,
                    child_pid=pid,
                    child_process_group=pid,
                    child_session=pid,
                    child_start_identity=f"synthetic-start:{pid}",
                    profile_sha256=layer_profile,
                    pre_exec_setsid_succeeded=True,
                    pre_exec_pid=pid,
                    pre_exec_process_group=pid,
                    pre_exec_session=pid,
                    pre_exec_nproc_soft=limit[0],
                    pre_exec_nproc_hard=limit[1],
                    nproc_soft=limit[0],
                    nproc_hard=limit[1],
                )
            )
    return observations


class NoChildProfileUnitTests(unittest.TestCase):
    def test_nested_seatbelt_denial_is_normalized_without_raw_stderr(self) -> None:
        observation = profile._parse_probe_output(
            layer="seatbelt",
            action="baseline",
            completed=subprocess.CompletedProcess(
                ("/usr/bin/sandbox-exec",),
                71,
                b"",
                b"sandbox-exec: sandbox_apply: Operation not permitted\n",
            ),
        )

        self.assertEqual(observation.outcome, "ambiguous")
        self.assertEqual(
            observation.detail,
            profile.PROBE_DETAIL_OUTER_SEATBELT_DENIED,
        )
        self.assertNotIn("sandbox_apply", observation.detail)

        killed_observation = profile._parse_probe_output(
            layer="combined",
            action="exec",
            completed=subprocess.CompletedProcess(
                ("/usr/bin/sandbox-exec",),
                -signal.SIGKILL,
                b"",
                b"",
            ),
        )
        self.assertEqual(killed_observation.outcome, "ambiguous")
        self.assertEqual(
            killed_observation.detail,
            profile.PROBE_DETAIL_KILLED_BEFORE_EVIDENCE,
        )

        with mock.patch.object(profile.json, "loads", side_effect=RecursionError):
            with self.assertRaisesRegex(ValueError, "not valid JSON"):
                profile._parse_preexec_state(b"{}")
            recursion_observation = profile._parse_probe_output(
                layer="seatbelt",
                action="baseline",
                completed=subprocess.CompletedProcess(
                    ("/usr/bin/sandbox-exec",), 0, b"{}", b""
                ),
            )
        self.assertEqual(recursion_observation.outcome, "ambiguous")
        self.assertIn("not canonical JSON", recursion_observation.detail)

    def test_nonexistent_probe_leader_uses_a_normalized_reason(self) -> None:
        error = ProcessLookupError(errno.ESRCH, "synthetic private path")
        detail = profile._leader_binding_error_detail(error)

        self.assertEqual(
            detail,
            profile.PROBE_DETAIL_LEADER_EXITED_BEFORE_BINDING,
        )
        self.assertNotIn("synthetic private path", detail)

    def test_hosted_fail_closed_signature_matches_production_blockers(self) -> None:
        from .run_hosted_no_child_fail_closed import (
            PROBE_ACTIONS,
            _expected_hosted_fail_closed_blockers,
            _matches_hosted_fail_closed_observations,
            _signature_diagnostics,
        )

        parent_limit = (256, 512)
        profile_sha256 = "a" * 64

        def build_evidence(
            bound_rlimit_actions: set[str],
            *,
            leader_exited_prefix_lengths: dict[str, int] | None = None,
        ) -> profile.CompatibilityEvidence:
            prefix_lengths = leader_exited_prefix_lengths or {}
            observations: list[profile.ProbeObservation] = []
            for layer_index, layer in enumerate(("rlimit", "seatbelt", "combined")):
                expected_limit = parent_limit if layer == "seatbelt" else (0, 0)
                expected_profile = None if layer == "rlimit" else profile_sha256
                for action_index, action in enumerate(PROBE_ACTIONS):
                    pid = 4000 + layer_index * 100 + action_index
                    bound = layer != "rlimit" or action in bound_rlimit_actions
                    numeric_prefix_length = 2 if bound else prefix_lengths.get(action, 0)
                    post_exec_limit = expected_limit if bound else (None, None)
                    observations.append(
                        profile.ProbeObservation(
                            layer=layer,
                            action=action,
                            outcome="ambiguous",
                            detail=(
                                profile.PROBE_DETAIL_KILLED_BEFORE_EVIDENCE
                                if bound
                                else profile.PROBE_DETAIL_LEADER_EXITED_BEFORE_BINDING
                            ),
                            child_pid=pid,
                            child_process_group=(
                                pid if numeric_prefix_length >= 1 else None
                            ),
                            child_session=pid if numeric_prefix_length >= 2 else None,
                            child_start_identity=(
                                f"darwin-proc-start:{pid}:1" if bound else None
                            ),
                            profile_sha256=expected_profile,
                            pre_exec_setsid_succeeded=True,
                            pre_exec_pid=pid,
                            pre_exec_process_group=pid,
                            pre_exec_session=pid,
                            pre_exec_nproc_soft=expected_limit[0],
                            pre_exec_nproc_hard=expected_limit[1],
                            nproc_soft=post_exec_limit[0],
                            nproc_hard=post_exec_limit[1],
                        )
                    )
            blockers = profile._probe_blockers(
                observations,
                parent_nproc=parent_limit,
                profile_sha256=profile_sha256,
            )
            return profile.CompatibilityEvidence(
                schema_version=profile.EVIDENCE_SCHEMA_VERSION,
                runtime_pin=GITHUB_HOSTED_LEGACY_RUNTIME_PIN,
                runtime=profile.RuntimeFingerprint(
                    platform="darwin",
                    system="Darwin",
                    macos_product_version="26.4",
                    macos_build_version="25E246",
                    darwin_release="25.4.0",
                    python_version=(3, 13, 0),
                    python_executable="/synthetic/python3.13",
                    effective_uid=501,
                ),
                sandbox_exec=None,
                probe_executable=None,
                alternate_executable=None,
                seatbelt_profile_sha256=profile_sha256,
                parent_nproc_before=parent_limit,
                parent_nproc_after=parent_limit,
                observations=tuple(observations),
                blockers=tuple(blockers),
            )

        def replace_observation(
            evidence: profile.CompatibilityEvidence,
            index: int,
            **changes: object,
        ) -> profile.CompatibilityEvidence:
            observations = list(evidence.observations)
            observations[index] = replace(observations[index], **changes)
            blockers = profile._probe_blockers(
                observations,
                parent_nproc=parent_limit,
                profile_sha256=profile_sha256,
            )
            return replace(
                evidence,
                observations=tuple(observations),
                blockers=tuple(blockers),
            )

        cases = (
            ("all-unbound", set(), {}, 72),
            ("pr174-full-numeric-prefix", set(), {"fork": 2}, 71),
            ("pgid-only-numeric-prefix", set(), {"fork": 1}, 72),
            ("baseline-bound", {"baseline"}, {}, 69),
            ("all-bound", set(PROBE_ACTIONS), {}, 48),
        )
        evidence_by_case: dict[str, profile.CompatibilityEvidence] = {}
        for (
            name,
            bound_rlimit_actions,
            leader_exited_prefix_lengths,
            expected_blocker_count,
        ) in cases:
            with self.subTest(name=name):
                evidence = build_evidence(
                    bound_rlimit_actions,
                    leader_exited_prefix_lengths=leader_exited_prefix_lengths,
                )
                evidence_by_case[name] = evidence
                expected_blockers = _expected_hosted_fail_closed_blockers(evidence)

                self.assertEqual(len(evidence.observations), 24)
                self.assertEqual(set(evidence.blockers), expected_blockers)
                self.assertEqual(len(evidence.blockers), expected_blocker_count)
                self.assertEqual(len(evidence.blockers), len(set(evidence.blockers)))
                self.assertTrue(_matches_hosted_fail_closed_observations(evidence))
                self.assertFalse(evidence.compatible)
                self.assertFalse(evidence.production_capable)
                diagnostics = _signature_diagnostics(
                    evidence,
                    expected_blockers=expected_blockers,
                    runtime_matches=True,
                    observation_signature_matches=True,
                )
                self.assertTrue(diagnostics["blockers_match"])
                self.assertTrue(diagnostics["observation_signature_matches"])
                self.assertTrue(diagnostics["parent_nproc_stable"])
                self.assertEqual(
                    diagnostics["missing_evidence"],
                    ["sandbox_exec", "probe_executable", "alternate_executable"],
                )
                self.assertEqual(len(diagnostics["observations"]), 24)

        pr174_evidence = evidence_by_case["pr174-full-numeric-prefix"]
        rlimit_fork_index = next(
            index
            for index, item in enumerate(pr174_evidence.observations)
            if (item.layer, item.action) == ("rlimit", "fork")
        )
        pr174_fork = pr174_evidence.observations[rlimit_fork_index]
        self.assertEqual(
            (pr174_fork.child_process_group, pr174_fork.child_session),
            (pr174_fork.pre_exec_pid, pr174_fork.pre_exec_pid),
        )
        self.assertNotIn(
            "rlimit-fork-post-exec-leader-binding-invalid",
            pr174_evidence.blockers,
        )
        self.assertIn("rlimit-fork-start-identity-is-missing", pr174_evidence.blockers)
        self.assertIn("rlimit-fork-post-exec-rlimit-is-invalid", pr174_evidence.blockers)

        pgid_only_evidence = evidence_by_case["pgid-only-numeric-prefix"]
        pgid_only_fork = pgid_only_evidence.observations[rlimit_fork_index]
        self.assertEqual(
            (pgid_only_fork.child_process_group, pgid_only_fork.child_session),
            (pgid_only_fork.pre_exec_pid, None),
        )
        self.assertIn(
            "rlimit-fork-post-exec-leader-binding-invalid",
            pgid_only_evidence.blockers,
        )

        negative_prefix_cases = (
            (
                "reverse-numeric-sample",
                {
                    "child_process_group": None,
                    "child_session": pr174_fork.pre_exec_pid,
                },
            ),
            (
                "wrong-numeric-sample",
                {
                    "child_process_group": pr174_fork.pre_exec_pid + 1,
                    "child_session": pr174_fork.pre_exec_pid + 1,
                },
            ),
            (
                "start-identity-present",
                {"child_start_identity": "darwin-proc-start:synthetic"},
            ),
            (
                "post-exec-nproc-present",
                {"nproc_soft": 0, "nproc_hard": 0},
            ),
        )
        for name, changes in negative_prefix_cases:
            with self.subTest(name=name):
                drifted = replace_observation(
                    pr174_evidence,
                    rlimit_fork_index,
                    **changes,
                )
                self.assertFalse(_matches_hosted_fail_closed_observations(drifted))
                self.assertEqual(
                    set(drifted.blockers),
                    _expected_hosted_fail_closed_blockers(drifted),
                )

        evidence = evidence_by_case["baseline-bound"]
        rlimit_index = next(
            index
            for index, item in enumerate(evidence.observations)
            if (item.layer, item.action) == ("rlimit", "baseline")
        )
        malformed_evidence = replace_observation(
            evidence,
            rlimit_index,
            detail=profile.PROBE_DETAIL_LEADER_EXITED_BEFORE_BINDING,
        )
        with self.subTest(name="malformed-mixed-shape"):
            self.assertFalse(
                _matches_hosted_fail_closed_observations(malformed_evidence)
            )
            self.assertEqual(
                set(malformed_evidence.blockers),
                _expected_hosted_fail_closed_blockers(malformed_evidence),
            )

        seatbelt_index = next(
            index
            for index, item in enumerate(evidence.observations)
            if (item.layer, item.action) == ("seatbelt", "baseline")
        )
        drifted_observations = list(evidence.observations)
        drifted_observations[seatbelt_index] = replace(
            drifted_observations[seatbelt_index],
            detail=profile.PROBE_DETAIL_OUTER_SEATBELT_DENIED,
        )
        self.assertFalse(
            _matches_hosted_fail_closed_observations(
                replace(evidence, observations=tuple(drifted_observations))
            )
        )

    def test_required_live_ci_fails_closed_on_runtime_pin_mismatch(self) -> None:
        runtime = profile.RuntimeFingerprint(
            platform="darwin",
            system="Darwin",
            macos_product_version="99.0",
            macos_build_version="99Z999",
            darwin_release="99.0.0",
            python_version=(3, 13, 0),
            python_executable="/synthetic/python3.13",
            effective_uid=501,
        )
        with (
            mock.patch.object(profile, "_runtime_fingerprint", return_value=runtime),
            mock.patch.dict(
                os.environ,
                {REQUIRE_LIVE_NO_CHILD_PROFILE_ENV: "1"},
                clear=False,
            ),
            self.assertRaisesRegex(
                AssertionError,
                "required live no-child profile check cannot skip",
            ),
        ):
            NoChildProfileDarwinIntegrationTests.setUpClass()

    def test_unrequired_runtime_pin_mismatch_remains_skippable(self) -> None:
        runtime = profile.RuntimeFingerprint(
            platform="darwin",
            system="Darwin",
            macos_product_version="99.0",
            macos_build_version="99Z999",
            darwin_release="99.0.0",
            python_version=(3, 13, 0),
            python_executable="/synthetic/python3.13",
            effective_uid=501,
        )
        with (
            mock.patch.object(profile, "_runtime_fingerprint", return_value=runtime),
            mock.patch.dict(
                os.environ,
                {REQUIRE_LIVE_NO_CHILD_PROFILE_ENV: ""},
                clear=False,
            ),
            self.assertRaisesRegex(
                unittest.SkipTest,
                "live no-child profile checks require the exact pinned",
            ),
        ):
            NoChildProfileDarwinIntegrationTests.setUpClass()

    def test_hosted_live_runtime_profile_is_exact_and_test_only(self) -> None:
        pin = GITHUB_HOSTED_LEGACY_RUNTIME_PIN
        self.assertEqual(
            set(GITHUB_HOSTED_RUNTIME_PINS),
            {
                "github-macos-26-arm64-26.4-25E246",
                "github-macos-26-arm64-26.5.2-25F84",
            },
        )
        self.assertEqual(pin.macos_product_version, "26.4")
        self.assertEqual(pin.macos_build_version, "25E246")
        self.assertEqual(pin.darwin_release, "25.4.0")
        self.assertEqual(
            pin.sandbox_exec_sha256,
            "d1ee30dbde955aaa75c7f801fdfea4df05b10129454d7982eb6453f771436d42",
        )
        self.assertNotEqual(pin, profile.PINNED_RUNTIME)
        current = GITHUB_HOSTED_RUNTIME_PINS["github-macos-26-arm64-26.5.2-25F84"]
        self.assertEqual(current.macos_product_version, "26.5.2")
        self.assertEqual(current.macos_build_version, "25F84")
        self.assertEqual(current.darwin_release, "25.5.0")
        self.assertEqual(
            current.sandbox_exec_sha256,
            "8290e4be7387a0df83cd1559e86afd880464f269450573d012795761fe298f16",
        )
        self.assertEqual(current, profile.PINNED_RUNTIME)

    def test_hosted_runtime_selector_requires_an_exact_reviewed_match(self) -> None:
        from tests.run_hosted_no_child_fail_closed import (
            _select_hosted_runtime_profile,
        )

        cases = (
            (
                "github-macos-26-arm64-26.4-25E246",
                "26.4",
                "25E246",
                "25.4.0",
                (3, 13, 0),
            ),
            (
                "github-macos-26-arm64-26.5.2-25F84",
                "26.5.2",
                "25F84",
                "25.5.0",
                (3, 13, 1),
            ),
            (None, "26.6", "25G100", "25.6.0", (3, 13, 0)),
            (None, "26.5.2", "25F84", "25.5.0", (3, 14, 0)),
        )
        for expected_name, product, build, darwin, python_version in cases:
            with self.subTest(
                product=product,
                build=build,
                darwin=darwin,
                python_version=python_version,
            ):
                runtime = profile.RuntimeFingerprint(
                    platform="darwin",
                    system="Darwin",
                    macos_product_version=product,
                    macos_build_version=build,
                    darwin_release=darwin,
                    python_version=python_version,
                    python_executable="/synthetic/python3.13",
                    effective_uid=501,
                )
                selected = _select_hosted_runtime_profile(runtime)
                if expected_name is None:
                    self.assertIsNone(selected)
                else:
                    self.assertIsNotNone(selected)
                    assert selected is not None
                    self.assertEqual(selected[0], expected_name)
                    self.assertEqual(
                        selected[1],
                        GITHUB_HOSTED_RUNTIME_PINS[expected_name],
                    )

    def test_custom_runtime_pin_evidence_is_not_production_capable(self) -> None:
        evidence = profile.CompatibilityEvidence(
            schema_version=profile.EVIDENCE_SCHEMA_VERSION,
            runtime_pin=GITHUB_HOSTED_LEGACY_RUNTIME_PIN,
            runtime=profile.RuntimeFingerprint(
                platform="darwin",
                system="Darwin",
                macos_product_version="26.4",
                macos_build_version="25E246",
                darwin_release="25.4.0",
                python_version=(3, 13, 0),
                python_executable="/synthetic/python3.13",
                effective_uid=501,
            ),
            sandbox_exec=None,
            probe_executable=None,
            alternate_executable=None,
            seatbelt_profile_sha256=None,
            parent_nproc_before=None,
            parent_nproc_after=None,
            observations=(),
            blockers=(),
        )

        self.assertTrue(evidence.compatible)
        self.assertFalse(evidence.production_capable)

    def test_preexec_order_establishes_leader_before_zeroing_nproc(self) -> None:
        events: list[str] = []
        process_groups = iter((99, 123))

        def get_process_group() -> int:
            event = "getpgrp-before" if not events else "getpgrp-after"
            events.append(event)
            return next(process_groups)

        with (
            mock.patch.object(profile.os, "getpid", return_value=123),
            mock.patch.object(
                profile.os,
                "getpgrp",
                side_effect=get_process_group,
            ),
            mock.patch.object(
                profile.os,
                "setsid",
                side_effect=lambda: events.append("setsid"),
            ) as setsid,
            mock.patch.object(
                profile.os,
                "getsid",
                side_effect=lambda _pid: events.append("getsid") or 123,
            ),
            mock.patch.object(
                profile,
                "_set_zero_nproc_limit",
                side_effect=lambda: events.append("setrlimit"),
            ),
            mock.patch.object(
                profile.resource,
                "getrlimit",
                side_effect=lambda _kind: events.append("getrlimit") or (0, 0),
            ),
            mock.patch.object(
                profile.os,
                "write",
                side_effect=lambda _fd, payload: events.append("write") or len(payload),
            ),
            mock.patch.object(
                profile.os,
                "close",
                side_effect=lambda _fd: events.append("close"),
            ),
        ):
            profile._establish_preexec_state(
                status_write_fd=77,
                set_nproc_zero=True,
            )

        setsid.assert_called_once_with()
        self.assertEqual(
            events,
            [
                "getpgrp-before",
                "setsid",
                "getpgrp-after",
                "getsid",
                "setrlimit",
                "getrlimit",
                "write",
                "close",
            ],
        )

    def test_profile_is_versioned_and_allows_only_the_exact_initial_binary(
        self,
    ) -> None:
        source = pathlib.Path(sys.executable).resolve()
        seatbelt = profile.build_seatbelt_profile(source)

        self.assertTrue(seatbelt.startswith("(version 1)\n"))
        self.assertIn("(deny process-fork)", seatbelt)
        self.assertIn("(deny process-exec*)", seatbelt)
        self.assertIn(
            f'(allow process-exec (literal "{source}"))',
            seatbelt,
        )
        self.assertNotIn("/usr/bin/true", seatbelt)

    def test_additional_seatbelt_rules_accept_complete_deny_expressions(
        self,
    ) -> None:
        source = pathlib.Path(sys.executable).resolve()
        rules = "\n".join(
            (
                "(deny file-read*)",
                '(deny file-write* (literal "/tmp/review;safe"))',
                '(deny file-write* (subpath "/tmp/review root"))',
                "",
            )
        )

        rendered = profile.build_seatbelt_profile(
            source,
            additional_rules=rules,
        )

        for rule in rules.splitlines():
            self.assertIn(rule, rendered.splitlines())

    def test_additional_seatbelt_rules_reject_parser_bypass_forms(self) -> None:
        source = pathlib.Path(sys.executable).resolve()
        excessive_nesting = (
            "(deny file-read* " + "(require-all " * 33 + '(literal "/tmp")' + ")" * 34
        )
        cases = {
            "same-line-allow": "(deny file-read*) (allow process-fork)",
            "same-line-second-deny": "(deny file-read*) (deny network*)",
            "direct-allow": "(allow process-fork)",
            "trailing-comment": "(deny file-read*) ; (allow process-fork)",
            "comment-prefix": "; (deny file-read*)",
            "datum-comment": "#;(deny file-read*)\n(allow process-fork)",
            "quoted-expression": "'(deny file-read*)",
            "nested-allow": "(deny file-read* (require-any (allow process-fork)))",
            "open-expression": "(deny file-read*",
            "extra-close": "(deny file-read*))",
            "invalid-string-escape": '(deny file-read* (literal "/tmp/\\q"))',
            "open-string": '(deny file-read* (literal "/tmp))',
            "non-symbol-form-head": '(deny file-read* ((literal) "/tmp"))',
            "excessive-nesting": excessive_nesting,
        }

        for label, rules in cases.items():
            with (
                self.subTest(label=label),
                self.assertRaises(profile.NoChildProfileError),
            ):
                profile.build_seatbelt_profile(
                    source,
                    additional_rules=rules,
                )

    @unittest.skipUnless(
        sys.platform == "darwin" and sys.version_info[:2] == (3, 13),
        "Darwin with Python 3.13 is required",
    )
    def test_custodied_snapshot_profile_uses_fd_attestations_and_explicit_roots(
        self,
    ) -> None:
        with owned_temporary_directory("owner-snapshot-profile-") as temporary:
            root = temporary.resolve(strict=True)
            os.chmod(root, 0o700)
            attestation = _build_owner_snapshot_attestation(
                root,
                source=profile.python_runtime_executable(),
            )
            writable_path = root / "writable"
            writable_path.mkdir(mode=0o700)
            writable_fd = os.open(
                writable_path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                writable = profile.attest_writable_root(
                    writable_path,
                    directory_fd=writable_fd,
                )
                (writable_path / "prepared-before-launch").write_text(
                    "mutable contents\n",
                    encoding="ascii",
                )
                with (
                    mock.patch.object(
                        profile,
                        "probe_compatibility",
                        return_value=mock.sentinel.compatibility,
                    ),
                    mock.patch.object(profile, "require_compatible"),
                    mock.patch.object(profile, "authenticate_executable") as ordinary,
                ):
                    prepared = profile.prepare_custodied_snapshot_no_child_profile(
                        attestation,
                        writable_roots=(writable,),
                    )

                ordinary.assert_not_called()
                self.assertEqual(
                    prepared.owner_snapshot_attestation,
                    attestation,
                )
                self.assertEqual(prepared.writable_roots, (writable,))
                lines = prepared.seatbelt_profile.splitlines()
                self.assertIn("(deny file-write*)", lines)
                self.assertIn("(deny file-link)", lines)
                self.assertIn(
                    f'(allow file-write* (subpath "{writable_path}"))',
                    lines,
                )
                allowed_exec = {
                    line for line in lines if line.startswith("(allow process-exec ")
                }
                self.assertEqual(
                    allowed_exec,
                    {
                        f'(allow process-exec (literal "{attestation.snapshot.executable_path}"))',
                        f'(allow process-exec (literal "{profile.SANDBOX_EXEC}"))',
                    },
                )
                self.assertLess(
                    lines.index("(deny file-write*)"),
                    lines.index(f'(allow file-write* (subpath "{writable_path}"))'),
                )
                self.assertLess(
                    lines.index("(deny file-link)"),
                    lines.index(f'(allow file-write* (subpath "{writable_path}"))'),
                )
                with (
                    mock.patch.object(profile, "require_compatible"),
                    mock.patch.object(profile, "_require_live_runtime"),
                    mock.patch.object(profile.os, "fork") as fork,
                    self.assertRaisesRegex(
                        ValueError,
                        "custody and writable-root descriptors cannot be inherited",
                    ),
                ):
                    profile.launch_prepared_no_child_process(
                        prepared,
                        [attestation.snapshot.executable_path],
                        cwd=root,
                        pass_fds=(attestation.executable_fd,),
                    )
                fork.assert_not_called()
            finally:
                os.close(writable_fd)
                _close_owner_snapshot_attestation(attestation)

    @unittest.skipUnless(
        sys.platform == "darwin" and sys.version_info[:2] == (3, 13),
        "Darwin with Python 3.13 is required",
    )
    def test_data_volume_alias_cannot_be_attested_as_snapshot_writable_root(
        self,
    ) -> None:
        with owned_temporary_directory("owner-snapshot-alias-") as temporary:
            root = temporary.resolve(strict=True)
            os.chmod(root, 0o700)
            attestation = _build_owner_snapshot_attestation(
                root,
                source=profile.python_runtime_executable(),
            )
            snapshot_parent = pathlib.Path(attestation.snapshot.parent_path)
            data_alias = pathlib.Path(
                "/System/Volumes/Data"
            ) / snapshot_parent.relative_to("/")
            try:
                alias_fd = os.open(
                    data_alias,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
            except OSError as error:
                _close_owner_snapshot_attestation(attestation)
                self.skipTest(f"macOS Data firmlink alias is unavailable: {error}")
            try:
                try:
                    writable = profile.attest_writable_root(
                        data_alias,
                        directory_fd=alias_fd,
                    )
                except profile.ExecutableAuthenticationError as error:
                    self.assertRegex(
                        str(error),
                        "ancestor access policy|untrusted writer|untrusted owner",
                    )
                    return
                with (
                    mock.patch.object(
                        profile,
                        "probe_compatibility",
                        return_value=mock.sentinel.compatibility,
                    ),
                    mock.patch.object(profile, "require_compatible"),
                    self.assertRaisesRegex(
                        profile.ExecutableAuthenticationError,
                        "overlaps the protected snapshot through a path alias",
                    ),
                ):
                    profile.prepare_custodied_snapshot_no_child_profile(
                        attestation,
                        writable_roots=(writable,),
                    )
            finally:
                os.close(alias_fd)
                _close_owner_snapshot_attestation(attestation)

    def test_snapshot_launch_revalidation_checks_current_single_link_policy(
        self,
    ) -> None:
        with owned_temporary_directory("snapshot-link-policy-") as temporary:
            root = temporary.resolve(strict=True)
            root.chmod(0o700)
            source = root / "source"
            _write_synthetic_macho(source)
            attestation = _build_owner_snapshot_attestation(
                root,
                source=source,
            )
            snapshot_path = pathlib.Path(attestation.snapshot.executable_path)
            alias_path = snapshot_path.with_name("codex-hard-link")
            try:
                with (
                    mock.patch.object(
                        profile,
                        "probe_compatibility",
                        return_value=mock.sentinel.compatibility,
                    ),
                    mock.patch.object(profile, "require_compatible"),
                ):
                    prepared = profile.prepare_custodied_snapshot_no_child_profile(
                        attestation,
                        writable_roots=(),
                    )
                expected_identity = attestation.snapshot.executable_identity
                self.assertEqual(
                    expected_identity.file_protected_key(),
                    replace(
                        expected_identity,
                        link_count=expected_identity.link_count + 1,
                    ).file_protected_key(),
                )
                os.link(snapshot_path, alias_path)
                self.assertEqual(os.stat(snapshot_path).st_nlink, 2)
                with self.assertRaisesRegex(
                    profile.ExecutableAuthenticationError,
                    "access policy has an unsafe hard-link count",
                ):
                    profile._revalidate_prepared_profile(prepared)
            finally:
                alias_path.unlink(missing_ok=True)
                _close_owner_snapshot_attestation(attestation)

    def test_error_pipe_setup_failure_closes_every_created_descriptor(self) -> None:
        error_read, error_write = os.pipe()
        owner = profile._NoChildLaunchReceiptOwner()
        with (
            mock.patch.object(
                profile.os,
                "pipe",
                return_value=(error_read, error_write),
            ),
            mock.patch.object(
                profile.os,
                "set_inheritable",
                side_effect=(None, OSError(errno.EIO, "injected cloexec failure")),
            ),
            self.assertRaisesRegex(OSError, "injected cloexec failure"),
        ):
            profile._open_launch_error_pipe(owner)

        self.assertTrue(owner.require_receipt().control_pipes_closed)
        for descriptor in (error_read, error_write):
            with self.subTest(descriptor=descriptor):
                with self.assertRaises(OSError) as raised:
                    os.fstat(descriptor)
                self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_error_pipe_creation_failure_proves_no_descriptors_created(self) -> None:
        owner = profile._NoChildLaunchReceiptOwner()
        with (
            mock.patch.object(
                profile.os,
                "pipe",
                side_effect=OSError(errno.EMFILE, "injected pipe creation failure"),
            ),
            self.assertRaisesRegex(OSError, "injected pipe creation failure"),
        ):
            profile._open_launch_error_pipe(owner)

        receipt = owner.require_receipt()
        self.assertTrue(receipt.pipe_call_started)
        self.assertFalse(receipt.pipe_call_completed)
        self.assertTrue(receipt.pipe_failure_proven)
        self.assertTrue(receipt.control_pipes_closed)
        self.assertEqual(receipt.error_read_fd, -1)
        self.assertEqual(receipt.error_write_fd, -1)
        self.assertEqual(receipt.error_read_close_outcome, "not-created")
        self.assertEqual(receipt.error_write_close_outcome, "not-created")

    def test_error_pipe_worker_preowns_receipt_before_pipe_result(self) -> None:
        owner = profile._NoChildLaunchReceiptOwner()
        caller_thread = threading.get_ident()
        opened_descriptors: list[int] = []
        original_pipe = os.pipe

        def open_pipe() -> tuple[int, int]:
            self.assertNotEqual(threading.get_ident(), caller_thread)
            receipt = owner.require_receipt()
            self.assertTrue(receipt.pipe_call_started)
            self.assertFalse(receipt.pipe_call_completed)
            self.assertEqual(receipt.error_read_fd, -1)
            self.assertEqual(receipt.error_write_fd, -1)
            self.assertEqual(receipt.error_read_close_outcome, "not-created")
            self.assertEqual(receipt.error_write_close_outcome, "not-created")
            result = original_pipe()
            opened_descriptors.extend(result)
            return result

        receipt: profile._NoChildLaunchReceipt | None = None
        try:
            with mock.patch.object(profile.os, "pipe", side_effect=open_pipe):
                receipt = profile._open_launch_error_pipe(owner)
            self.assertTrue(receipt.pipe_call_completed)
            self.assertTrue(owner.owns(receipt))
            self.assertEqual(
                (receipt.error_read_fd, receipt.error_write_fd),
                tuple(opened_descriptors),
            )
        finally:
            if receipt is not None:
                receipt.close_error_read([])
                receipt.close_error_write([])
            for descriptor in opened_descriptors:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_error_pipe_return_store_interrupt_closes_prepublished_fds(
        self,
    ) -> None:
        target_offset = _call_followup_offset(
            profile._fork_with_launch_error_pipe,
            called_name="_open_launch_error_pipe",
            following_opname="STORE_FAST",
            following_argval="receipt",
        )
        prepared = _synthetic_prepared_launch()
        parent_pid = os.getpid()
        interruption = SystemExit("injected pipe return-to-receipt-store interrupt")
        armed = True
        opened_descriptors: list[int] = []
        original_pipe = os.pipe

        def open_pipe() -> tuple[int, int]:
            result = original_pipe()
            opened_descriptors.extend(result)
            return result

        def trace(frame, event, _arg):
            nonlocal armed
            if os.getpid() != parent_pid:
                return None
            if frame.f_code is profile._fork_with_launch_error_pipe.__code__:
                frame.f_trace_opcodes = True
                if event == "opcode" and armed and frame.f_lasti == target_offset:
                    armed = False
                    raise interruption
            return trace

        previous_trace = sys.gettrace()
        try:
            with (
                mock.patch.object(profile, "require_compatible"),
                mock.patch.object(profile, "_require_live_runtime"),
                mock.patch.object(profile, "_revalidate_prepared_profile"),
                mock.patch.object(profile, "prove_exec_budget"),
                mock.patch.object(profile.os, "pipe", side_effect=open_pipe),
                mock.patch.object(profile.os, "fork") as fork,
            ):
                sys.settrace(trace)
                try:
                    with self.assertRaises(SystemExit) as caught:
                        profile.launch_prepared_no_child_process(
                            prepared,
                            [prepared.executable.path],
                            cwd="/",
                            environment={},
                        )
                finally:
                    sys.settrace(previous_trace)

            self.assertIs(caught.exception, interruption)
            self.assertFalse(armed)
            fork.assert_not_called()
            self.assertEqual(len(opened_descriptors), 2)
            for descriptor in opened_descriptors:
                with self.assertRaises(OSError) as descriptor_error:
                    os.fstat(descriptor)
                self.assertEqual(descriptor_error.exception.errno, errno.EBADF)
        finally:
            sys.settrace(previous_trace)
            for descriptor in opened_descriptors:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_fork_failure_closes_both_error_pipe_descriptors(self) -> None:
        error_read, error_write = os.pipe()
        owner = profile._NoChildLaunchReceiptOwner()
        with (
            mock.patch.object(
                profile,
                "_open_launch_error_pipe",
                side_effect=_publish_synthetic_pipe_receipt(
                    error_read=error_read,
                    error_write=error_write,
                ),
            ),
            mock.patch.object(
                profile.os,
                "fork",
                side_effect=OSError(errno.EAGAIN, "injected fork failure"),
            ),
            self.assertRaisesRegex(OSError, "injected fork failure"),
        ):
            profile._fork_with_launch_error_pipe(owner)

        self.assertIsNotNone(owner.receipt)
        assert owner.receipt is not None
        self.assertTrue(owner.receipt.fork_failure_proven)
        self.assertTrue(owner.receipt.control_pipes_closed)
        for descriptor in (error_read, error_write):
            with self.subTest(descriptor=descriptor):
                with self.assertRaises(OSError) as raised:
                    os.fstat(descriptor)
                self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_terminate_and_reap_uses_a_bounded_nonblocking_wait(self) -> None:
        with (
            mock.patch.object(profile.os, "killpg") as killpg,
            mock.patch.object(
                profile.os,
                "waitpid",
                return_value=(0, 0),
            ) as waitpid,
            mock.patch.object(
                profile.time,
                "monotonic",
                side_effect=(100.0, 106.0),
            ),
            mock.patch.object(profile.time, "sleep") as sleep,
            self.assertRaisesRegex(
                TimeoutError,
                "did not exit before deadline",
            ),
        ):
            profile._terminate_and_reap(424242)

        killpg.assert_called_once_with(424242, signal.SIGKILL)
        waitpid.assert_called_once_with(424242, os.WNOHANG)
        sleep.assert_not_called()

    def _assert_launch_opcode_interrupt_closes_exact_child(
        self,
        *,
        target_code: object,
        target_offset: int,
        interruption: BaseException,
    ) -> None:
        prepared = _synthetic_prepared_launch()
        error_read, error_write = os.pipe()
        parent_pid = os.getpid()
        armed = True
        settled_pids: list[int] = []
        receipts: list[profile._NoChildLaunchReceipt] = []
        real_terminate_and_reap = profile._terminate_and_reap
        publish_pipe_receipt = _publish_synthetic_pipe_receipt(
            error_read=error_read,
            error_write=error_write,
        )

        def terminate_and_reap(pid: int) -> None:
            settled_pids.append(pid)
            real_terminate_and_reap(pid)

        def open_pipe(
            owner: profile._NoChildLaunchReceiptOwner,
        ) -> profile._NoChildLaunchReceipt:
            receipt = publish_pipe_receipt(owner)
            receipts.append(receipt)
            return receipt

        def trace(frame, event, _arg):
            nonlocal armed
            if os.getpid() != parent_pid:
                return None
            if frame.f_code is target_code:
                frame.f_trace_opcodes = True
                if event == "opcode" and armed and frame.f_lasti == target_offset:
                    armed = False
                    raise interruption
            return trace

        previous_trace = sys.gettrace()
        leader_pid: int | None = None
        try:
            with (
                mock.patch.object(profile, "require_compatible"),
                mock.patch.object(profile, "_require_live_runtime"),
                mock.patch.object(profile, "_revalidate_prepared_profile"),
                mock.patch.object(profile, "prove_exec_budget"),
                mock.patch.object(
                    profile,
                    "_open_launch_error_pipe",
                    side_effect=open_pipe,
                ),
                mock.patch.object(
                    profile,
                    "_launch_child",
                    new=_hold_synthetic_launch_child,
                ),
                mock.patch.object(
                    profile,
                    "_terminate_and_reap",
                    side_effect=terminate_and_reap,
                ),
            ):
                sys.settrace(trace)
                try:
                    with self.assertRaises(type(interruption)) as caught:
                        profile.launch_prepared_no_child_process(
                            prepared,
                            [prepared.executable.path],
                            cwd="/",
                            environment={},
                        )
                finally:
                    sys.settrace(previous_trace)

            self.assertIs(caught.exception, interruption)
            self.assertFalse(armed)
            self.assertEqual(len(receipts), 1)
            self.assertTrue(receipts[0].fork_call_completed)
            self.assertFalse(receipts[0].fork_failure_proven)
            self.assertTrue(receipts[0].leader_receipt_received)
            self.assertEqual(len(settled_pids), 1)
            leader_pid = settled_pids[0]
            with self.assertRaises(ChildProcessError):
                os.waitpid(leader_pid, os.WNOHANG)
            with self.assertRaises(ProcessLookupError):
                os.killpg(leader_pid, 0)
            for descriptor in (error_read, error_write):
                with self.assertRaises(OSError) as descriptor_error:
                    os.fstat(descriptor)
                self.assertEqual(descriptor_error.exception.errno, errno.EBADF)
        finally:
            sys.settrace(previous_trace)
            if leader_pid is not None:
                try:
                    os.killpg(leader_pid, signal.SIGKILL)
                except ProcessLookupError:
                    try:
                        os.kill(leader_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    os.waitpid(leader_pid, 0)
                except ChildProcessError:
                    pass
            for descriptor in (error_read, error_write):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_fork_call_to_pid_store_interrupt_closes_exact_child(self) -> None:
        target_offset = _call_followup_offset(
            profile._fork_with_launch_error_pipe,
            called_name="fork",
            following_opname="STORE_FAST",
            following_argval="pid",
        )
        self._assert_launch_opcode_interrupt_closes_exact_child(
            target_code=profile._fork_with_launch_error_pipe.__code__,
            target_offset=target_offset,
            interruption=SystemExit("injected fork CALL-to-pid-STORE interruption"),
        )

    def test_fork_call_to_pid_store_oserror_settles_exact_child(self) -> None:
        target_offset = _call_followup_offset(
            profile._fork_with_launch_error_pipe,
            called_name="fork",
            following_opname="STORE_FAST",
            following_argval="pid",
        )
        self._assert_launch_opcode_interrupt_closes_exact_child(
            target_code=profile._fork_with_launch_error_pipe.__code__,
            target_offset=target_offset,
            interruption=OSError(
                errno.EINTR,
                "injected post-return fork OSError",
            ),
        )

    def test_launch_receipt_ambiguous_close_never_closes_reused_fd(self) -> None:
        error_read, error_write = os.pipe()
        receipt = profile._NoChildLaunchReceipt(
            creator_pid=os.getpid(),
            error_read_fd=error_read,
            error_write_fd=error_write,
        )
        original_close = os.close

        def close_then_interrupt(descriptor: int) -> None:
            self.assertEqual(receipt.error_read_fd, descriptor)
            self.assertEqual(
                receipt.error_read_close_outcome,
                "close-outcome-unproven",
            )
            original_close(descriptor)
            raise KeyboardInterrupt("injected close-result interruption")

        try:
            with (
                mock.patch.object(
                    profile.os,
                    "close",
                    side_effect=close_then_interrupt,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                receipt.close_error_read()

            self.assertEqual(receipt.error_read_fd, error_read)
            self.assertEqual(
                receipt.error_read_close_outcome,
                "close-outcome-unproven",
            )
            replacement_fd = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
            if replacement_fd != error_read:
                os.dup2(replacement_fd, error_read)
                os.close(replacement_fd)
                replacement_fd = error_read
            try:
                failures: list[str] = []
                with mock.patch.object(profile.os, "close") as retry_close:
                    self.assertFalse(receipt.close_error_read(failures))
                retry_close.assert_not_called()
                self.assertEqual(failures, [])
                os.fstat(replacement_fd)
            finally:
                os.close(replacement_fd)
        finally:
            receipt.close_error_write([])

    def test_ambiguous_pipe_close_publishes_typed_descriptor_retention(
        self,
    ) -> None:
        prepared = _synthetic_prepared_launch()
        error_read, error_write = os.pipe()
        receipt = profile._NoChildLaunchReceipt(
            creator_pid=os.getpid(),
            error_read_fd=error_read,
            error_write_fd=error_write,
        )
        owner = profile._NoChildLaunchReceiptOwner()
        owner.publish(receipt)
        original_close = os.close

        def close_with_ambiguous_read(descriptor: int) -> None:
            original_close(descriptor)
            if descriptor == error_read:
                raise KeyboardInterrupt("injected close-result interruption")

        try:
            with (
                mock.patch.object(
                    profile.os,
                    "close",
                    side_effect=close_with_ambiguous_read,
                ),
                self.assertRaises(profile.NoChildLaunchClosureUnproven) as caught,
            ):
                profile._settle_owned_launch_after_base_exception(
                    owner,
                    prepared=prepared,
                    exec_acknowledged=False,
                    leader_binding_complete=False,
                    trigger=RuntimeError("synthetic pre-fork failure"),
                )

            self.assertFalse(caught.exception.evidence.control_pipes_closed)
            self.assertEqual(receipt.error_read_fd, error_read)
            self.assertEqual(
                receipt.error_read_close_outcome,
                "close-outcome-unproven",
            )
            self.assertIn(error_read, caught.exception.retained_resources)
            self.assertIn(receipt, caught.exception.retained_resources)
            self.assertIn(owner, caught.exception.retained_resources)
        finally:
            for descriptor in (error_read, error_write):
                try:
                    original_close(descriptor)
                except OSError:
                    pass

    def test_launch_helper_return_to_unpack_interrupt_closes_exact_child(
        self,
    ) -> None:
        target_offset = _call_followup_offset(
            profile.launch_prepared_no_child_process,
            called_name="_fork_with_launch_error_pipe",
            following_opname="UNPACK_SEQUENCE",
        )
        self._assert_launch_opcode_interrupt_closes_exact_child(
            target_code=profile.launch_prepared_no_child_process.__code__,
            target_offset=target_offset,
            interruption=SystemExit(
                "injected launch helper return-to-UNPACK interruption"
            ),
        )

    def test_probe_pipe_setup_rolls_back_every_partial_initialization(self) -> None:
        release_pair = os.pipe()
        with (
            mock.patch.object(
                profile.os,
                "pipe",
                side_effect=(
                    release_pair,
                    OSError(errno.EMFILE, "injected second pipe failure"),
                ),
            ),
            self.assertRaisesRegex(OSError, "injected second pipe failure"),
        ):
            profile._open_probe_control_pipes()
        for descriptor in release_pair:
            with self.assertRaises(OSError) as raised:
                os.fstat(descriptor)
            self.assertEqual(raised.exception.errno, errno.EBADF)

        release_pair = os.pipe()
        status_pair = os.pipe()
        real_set_inheritable = os.set_inheritable
        calls = 0

        def fail_third_set_inheritable(descriptor: int, inheritable: bool) -> None:
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError(errno.EIO, "injected probe cloexec failure")
            real_set_inheritable(descriptor, inheritable)

        with (
            mock.patch.object(
                profile.os,
                "pipe",
                side_effect=(release_pair, status_pair),
            ),
            mock.patch.object(
                profile.os,
                "set_inheritable",
                side_effect=fail_third_set_inheritable,
            ),
            self.assertRaisesRegex(OSError, "injected probe cloexec failure"),
        ):
            profile._open_probe_control_pipes()
        for descriptor in (*release_pair, *status_pair):
            with self.assertRaises(OSError) as raised:
                os.fstat(descriptor)
            self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_probe_ambiguous_control_close_never_retries_reused_fd(self) -> None:
        release_read, release_write = os.pipe()
        control_descriptors = profile._ProbeControlDescriptorOwner.from_role_pairs(
            (
                ("release-read", release_read),
                ("release-write", release_write),
            )
        )
        original_close = os.close
        replacement_fd: int | None = None

        def close_reuse_then_interrupt(descriptor: int) -> None:
            nonlocal replacement_fd
            self.assertEqual(descriptor, release_read)
            self.assertEqual(
                control_descriptors.close_outcomes[descriptor],
                "close-outcome-unproven",
            )
            original_close(descriptor)
            opened = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
            if opened != descriptor:
                os.dup2(opened, descriptor, inheritable=False)
                original_close(opened)
            replacement_fd = descriptor
            raise OSError(
                errno.EINTR,
                "injected post-close OSError after immediate FD reuse",
            )

        try:
            with (
                mock.patch.object(
                    profile.os,
                    "close",
                    side_effect=close_reuse_then_interrupt,
                ),
                self.assertRaisesRegex(
                    OSError,
                    "injected post-close OSError",
                ),
            ):
                control_descriptors.close_descriptor(release_read)

            self.assertEqual(replacement_fd, release_read)
            self.assertEqual(
                control_descriptors.close_outcomes[release_read],
                "close-outcome-unproven",
            )
            close_calls: list[int] = []

            def close_remaining(descriptor: int) -> None:
                close_calls.append(descriptor)
                original_close(descriptor)

            failures: list[str] = []
            with mock.patch.object(
                profile.os,
                "close",
                side_effect=close_remaining,
            ):
                self.assertFalse(
                    profile._close_probe_control_descriptors(
                        control_descriptors,
                        failures,
                    )
                )
            self.assertNotIn(release_read, close_calls)
            self.assertIn("close-outcome-unproven", ";".join(failures))
            os.fstat(release_read)

            popen_owner = profile._ProbePopenOwner()
            with (
                mock.patch.object(profile.os, "close") as retry_close,
                self.assertRaises(profile.NoChildProbeSpawnOwnershipUnproven) as caught,
            ):
                profile._raise_probe_spawn_ownership_unproven(
                    popen_owner,
                    control_descriptors=control_descriptors,
                    cause=RuntimeError("synthetic cleanup transition"),
                    detail="exercise typed ambiguous descriptor retention",
                )
            retry_close.assert_not_called()
            evidence = caught.exception.evidence
            self.assertFalse(evidence.control_pipes_closed)
            close_evidence = {
                item.role: item for item in evidence.control_descriptor_close_evidence
            }
            self.assertEqual(
                close_evidence["release-read"].outcome,
                "close-outcome-unproven",
            )
            self.assertEqual(
                close_evidence["release-write"].outcome,
                "closed",
            )
            self.assertIn(
                control_descriptors,
                caught.exception.retained_resources,
            )
            self.assertNotIn(
                release_read,
                caught.exception.retained_resources,
            )
            self.assertIn(evidence, caught.exception.recovery_evidence)
            os.fstat(release_read)
        finally:
            for descriptor in (release_read, release_write):
                try:
                    original_close(descriptor)
                except OSError:
                    pass

    def test_probe_worker_uses_isolated_python_and_closed_launch_context(
        self,
    ) -> None:
        probe, alternate = _synthetic_probe_identities()
        with (
            mock.patch.dict(
                os.environ,
                {"PROBE_IMPORT_SHADOW": "must-not-cross"},
                clear=False,
            ),
            mock.patch.object(
                profile,
                "_spawn_owned_probe_process",
                side_effect=OSError(errno.ENOEXEC, "synthetic launch stop"),
            ) as popen,
            mock.patch.object(
                profile,
                "_revalidate_path_executed_executable",
                return_value=probe,
            ),
            mock.patch.object(
                profile,
                "_read_executable_identity",
                return_value=alternate,
            ),
            mock.patch.object(profile, "_read_bounded_pipe", return_value=b""),
        ):
            observation = profile._run_probe_case(
                layer="rlimit",
                action="baseline",
                probe_executable_attestation=_synthetic_probe_attestation(probe),
                alternate_executable=alternate,
                profile="(version 1)\n",
                python_home="/synthetic/python-home",
            )

        self.assertEqual(observation.outcome, "ambiguous")
        argv = popen.call_args.args[1]
        self.assertEqual(argv[:5], [probe.path, "-I", "-B", "-S", "-c"])
        self.assertEqual(popen.call_args.kwargs["cwd"], "/")
        self.assertEqual(
            popen.call_args.kwargs["env"],
            {
                "HOME": "/var/empty",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHOME": "/synthetic/python-home",
                "PYTHONNOUSERSITE": "1",
            },
        )

    def test_probe_base_exception_terminates_reaps_and_closes_every_pipe(
        self,
    ) -> None:
        probe, alternate = _synthetic_probe_identities()
        release_read, release_write = os.pipe()
        status_read, status_write = os.pipe()
        descriptors = (release_read, release_write, status_read, status_write)
        process = _SyntheticProbeProcess(
            pid=424240,
            communicate_error=KeyboardInterrupt("injected probe interrupt"),
        )

        def kill_process_group(process_group: int, signal_number: int) -> None:
            self.assertEqual(process_group, process.pid)
            if signal_number == 0:
                raise ProcessLookupError(errno.ESRCH, "synthetic empty group")
            self.assertEqual(signal_number, signal.SIGKILL)

        with (
            mock.patch.object(
                profile,
                "_open_probe_control_pipes",
                return_value=descriptors,
            ),
            mock.patch.object(
                profile,
                "_read_executable_identity",
                return_value=alternate,
            ),
            mock.patch.object(
                profile,
                "_revalidate_path_executed_executable",
                return_value=probe,
            ),
            mock.patch.object(
                profile,
                "_spawn_owned_probe_process",
                side_effect=_publish_synthetic_probe_process(process),
            ),
            mock.patch.object(
                profile,
                "_read_bounded_pipe",
                return_value=_successful_preexec_state(process.pid),
            ),
            mock.patch.object(profile.os, "getpgid", return_value=process.pid),
            mock.patch.object(profile.os, "getsid", return_value=process.pid),
            mock.patch.object(
                profile,
                "process_start_identity",
                return_value="synthetic-start",
            ),
            mock.patch.object(profile.os, "write", return_value=1),
            mock.patch.object(
                profile.os,
                "killpg",
                side_effect=kill_process_group,
            ) as killpg,
            self.assertRaisesRegex(
                KeyboardInterrupt,
                "injected probe interrupt",
            ),
        ):
            profile._run_probe_case(
                layer="rlimit",
                action="baseline",
                probe_executable_attestation=_synthetic_probe_attestation(probe),
                alternate_executable=alternate,
                profile="(version 1)\n",
                python_home="/synthetic/python-home",
            )

        self.assertEqual(process.wait_calls, 1)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        self.assertEqual(
            killpg.call_args_list,
            [
                mock.call(process.pid, signal.SIGKILL),
                mock.call(process.pid, 0),
            ],
        )
        for descriptor in descriptors:
            with self.assertRaises(OSError) as caught:
                os.fstat(descriptor)
            self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_probe_first_exec_revalidation_failure_prevents_popen(
        self,
    ) -> None:
        probe, alternate = _synthetic_probe_identities()
        release_read, release_write = os.pipe()
        status_read, status_write = os.pipe()
        descriptors = (release_read, release_write, status_read, status_write)
        revalidation_error = profile.ExecutableAuthenticationError(
            "synthetic immediate pre-exec attestation failure"
        )
        with (
            mock.patch.object(
                profile,
                "_open_probe_control_pipes",
                return_value=descriptors,
            ),
            mock.patch.object(
                profile,
                "_revalidate_path_executed_executable",
                side_effect=(probe, revalidation_error),
            ) as revalidate,
            mock.patch.object(
                profile,
                "_read_executable_identity",
                return_value=alternate,
            ),
            mock.patch.object(
                profile,
                "_spawn_owned_probe_process",
            ) as spawn_probe,
            self.assertRaisesRegex(
                profile.ExecutableAuthenticationError,
                "immediate pre-exec attestation failure",
            ),
        ):
            profile._run_probe_case(
                layer="rlimit",
                action="baseline",
                probe_executable_attestation=_synthetic_probe_attestation(probe),
                alternate_executable=alternate,
                profile="(version 1)\n",
                python_home="/synthetic/python-home",
            )

        self.assertEqual(revalidate.call_count, 2)
        spawn_probe.assert_not_called()
        for descriptor in descriptors:
            with self.assertRaises(OSError) as descriptor_error:
                os.fstat(descriptor)
            self.assertEqual(descriptor_error.exception.errno, errno.EBADF)

    def test_probe_popen_result_store_interrupt_uses_published_owner(
        self,
    ) -> None:
        instructions = list(dis.get_instructions(profile._run_probe_case))
        result_store_offsets: set[int] = set()
        for index, instruction in enumerate(instructions):
            if instruction.argval != "_spawn_owned_probe_process":
                continue
            for candidate_index in range(index + 1, len(instructions) - 1):
                if not instructions[candidate_index].opname.startswith("CALL"):
                    continue
                result_store = instructions[candidate_index + 1]
                if (
                    result_store.opname in {"STORE_FAST", "STORE_DEREF"}
                    and result_store.argval == "process"
                ):
                    result_store_offsets.add(result_store.offset)
                break
        self.assertEqual(len(result_store_offsets), 1)

        probe, alternate = _synthetic_probe_identities()
        release_read, release_write = os.pipe()
        status_read, status_write = os.pipe()
        descriptors = (release_read, release_write, status_read, status_write)
        process = _SyntheticProbeProcess(
            pid=424242,
            communicate_error=AssertionError("communicate must not run"),
        )
        interruption = SystemExit("injected Popen result-store interruption")
        armed = True

        def trace(frame, event, _arg):
            nonlocal armed
            if frame.f_code is profile._run_probe_case.__code__:
                frame.f_trace_opcodes = True
                if (
                    event == "opcode"
                    and armed
                    and frame.f_lasti in result_store_offsets
                ):
                    armed = False
                    raise interruption
            return trace

        previous_trace = sys.gettrace()
        with (
            mock.patch.object(
                profile,
                "_open_probe_control_pipes",
                return_value=descriptors,
            ),
            mock.patch.object(
                profile,
                "_revalidate_path_executed_executable",
                return_value=probe,
            ),
            mock.patch.object(
                profile,
                "_read_executable_identity",
                return_value=alternate,
            ),
            mock.patch.object(
                profile,
                "_spawn_owned_probe_process",
                side_effect=_publish_synthetic_probe_process(process),
            ),
            mock.patch.object(profile.os, "kill") as kill,
        ):
            sys.settrace(trace)
            try:
                with self.assertRaises(SystemExit) as caught:
                    profile._run_probe_case(
                        layer="rlimit",
                        action="baseline",
                        probe_executable_attestation=_synthetic_probe_attestation(
                            probe
                        ),
                        alternate_executable=alternate,
                        profile="(version 1)\n",
                        python_home="/synthetic/python-home",
                    )
            finally:
                sys.settrace(previous_trace)

        self.assertIs(caught.exception, interruption)
        self.assertFalse(armed)
        kill.assert_called_once_with(process.pid, signal.SIGKILL)
        self.assertEqual(process.wait_calls, 1)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        for descriptor in descriptors:
            with self.assertRaises(OSError) as descriptor_error:
                os.fstat(descriptor)
            self.assertEqual(descriptor_error.exception.errno, errno.EBADF)

    def test_probe_popen_interrupt_without_pid_returns_typed_retention(
        self,
    ) -> None:
        class PartialProbeProcess:
            def __init__(self) -> None:
                self.stdout = io.BytesIO()
                self.stderr = io.BytesIO()

        probe, alternate = _synthetic_probe_identities()
        release_read, release_write = os.pipe()
        status_read, status_write = os.pipe()
        descriptors = (release_read, release_write, status_read, status_write)
        partial_process = PartialProbeProcess()
        interruption = KeyboardInterrupt("injected Popen initialization interrupt")

        def interrupt_spawn(
            owner: profile._ProbePopenOwner,
            *_args: object,
            **_kwargs: object,
        ) -> None:
            owner.process = partial_process  # type: ignore[assignment]
            owner.ownership_published = True
            owner.popen_call_started = True
            raise interruption

        with (
            mock.patch.object(
                profile,
                "_open_probe_control_pipes",
                return_value=descriptors,
            ),
            mock.patch.object(
                profile,
                "_revalidate_path_executed_executable",
                return_value=probe,
            ),
            mock.patch.object(
                profile,
                "_read_executable_identity",
                return_value=alternate,
            ),
            mock.patch.object(
                profile,
                "_spawn_owned_probe_process",
                side_effect=interrupt_spawn,
            ),
            self.assertRaises(profile.NoChildProbeSpawnOwnershipUnproven) as caught,
        ):
            profile._run_probe_case(
                layer="rlimit",
                action="baseline",
                probe_executable_attestation=_synthetic_probe_attestation(probe),
                alternate_executable=alternate,
                profile="(version 1)\n",
                python_home="/synthetic/python-home",
            )

        evidence = caught.exception.evidence
        self.assertTrue(evidence.popen_call_started)
        self.assertFalse(evidence.popen_call_completed)
        self.assertTrue(evidence.ownership_published)
        self.assertIsNone(evidence.leader_pid)
        self.assertTrue(evidence.control_pipes_closed)
        self.assertTrue(evidence.output_pipes_closed)
        self.assertIn(partial_process, caught.exception.retained_resources)
        self.assertIn(evidence, caught.exception.recovery_evidence)
        self.assertTrue(partial_process.stdout.closed)
        self.assertTrue(partial_process.stderr.closed)
        for descriptor in descriptors:
            with self.assertRaises(OSError) as descriptor_error:
                os.fstat(descriptor)
            self.assertEqual(descriptor_error.exception.errno, errno.EBADF)

    def test_probe_unreaped_worker_returns_typed_retained_evidence(
        self,
    ) -> None:
        probe, alternate = _synthetic_probe_identities()
        release_read, release_write = os.pipe()
        status_read, status_write = os.pipe()
        descriptors = (release_read, release_write, status_read, status_write)
        process = _SyntheticProbeProcess(
            pid=424241,
            communicate_error=KeyboardInterrupt("injected probe interrupt"),
            wait_error=subprocess.TimeoutExpired("synthetic-probe", 1.0),
        )
        with (
            mock.patch.object(
                profile,
                "_open_probe_control_pipes",
                return_value=descriptors,
            ),
            mock.patch.object(
                profile,
                "_read_executable_identity",
                return_value=alternate,
            ),
            mock.patch.object(
                profile,
                "_revalidate_path_executed_executable",
                return_value=probe,
            ),
            mock.patch.object(
                profile,
                "_spawn_owned_probe_process",
                side_effect=_publish_synthetic_probe_process(process),
            ),
            mock.patch.object(
                profile,
                "_read_bounded_pipe",
                return_value=_successful_preexec_state(process.pid),
            ),
            mock.patch.object(profile.os, "getpgid", return_value=process.pid),
            mock.patch.object(profile.os, "getsid", return_value=process.pid),
            mock.patch.object(
                profile,
                "process_start_identity",
                return_value="synthetic-start",
            ),
            mock.patch.object(profile.os, "write", return_value=1),
            mock.patch.object(profile.os, "killpg") as killpg,
            self.assertRaises(profile.NoChildProbeClosureUnproven) as caught,
        ):
            profile._run_probe_case(
                layer="rlimit",
                action="baseline",
                probe_executable_attestation=_synthetic_probe_attestation(probe),
                alternate_executable=alternate,
                profile="(version 1)\n",
                python_home="/synthetic/python-home",
            )

        evidence = caught.exception.evidence
        self.assertTrue(evidence.worker_release_attempted)
        self.assertTrue(evidence.worker_released)
        self.assertFalse(evidence.communicate_completed)
        self.assertTrue(evidence.leader_binding_complete)
        self.assertTrue(evidence.process_group_bound)
        self.assertFalse(evidence.leader_reaped)
        self.assertFalse(evidence.process_group_empty)
        self.assertTrue(evidence.control_pipes_closed)
        self.assertTrue(evidence.output_pipes_closed)
        self.assertIn(process, caught.exception.retained_resources)
        self.assertIn(evidence, caught.exception.recovery_evidence)
        killpg.assert_called_once_with(process.pid, signal.SIGKILL)
        for descriptor in descriptors:
            with self.assertRaises(OSError) as descriptor_error:
                os.fstat(descriptor)
            self.assertEqual(descriptor_error.exception.errno, errno.EBADF)

    def test_post_acknowledgement_interrupt_terminates_and_reaps(self) -> None:
        executable = profile.ExecutableIdentity(
            path="/synthetic/app-server",
            device=1,
            inode=2,
            mode=stat.S_IFREG | 0o555,
            uid=0,
            gid=0,
            size=4,
            mtime_ns=1,
            ctime_ns=1,
            sha256="a" * 64,
        )
        prepared = profile.PreparedNoChildProfile(
            executable=executable,
            expected_sha256=executable.sha256,
            seatbelt_profile="(version 1)\n",
            evidence=mock.sentinel.compatibility,
        )
        error_read, error_write = os.pipe()
        with (
            mock.patch.object(profile, "require_compatible"),
            mock.patch.object(profile, "_require_live_runtime"),
            mock.patch.object(profile, "_revalidate_prepared_profile"),
            mock.patch.object(
                profile,
                "_fork_with_launch_error_pipe",
                side_effect=_publish_synthetic_launch_receipt(
                    pid=424242,
                    error_read=error_read,
                    error_write=error_write,
                ),
            ),
            mock.patch.object(
                profile.resource,
                "getrlimit",
                side_effect=((1, 1), KeyboardInterrupt("injected setup interrupt")),
            ),
            mock.patch.object(profile, "_terminate_and_reap") as terminate,
            self.assertRaisesRegex(KeyboardInterrupt, "injected setup interrupt"),
        ):
            profile.launch_prepared_no_child_process(
                prepared,
                [executable.path],
                cwd="/",
            )
        terminate.assert_called_once_with(424242)

    def test_binding_interrupt_terminates_and_reaps_or_retains_evidence(self) -> None:
        executable = profile.ExecutableIdentity(
            path="/synthetic/app-server",
            device=1,
            inode=2,
            mode=stat.S_IFREG | 0o555,
            uid=0,
            gid=0,
            size=4,
            mtime_ns=1,
            ctime_ns=1,
            sha256="a" * 64,
        )
        prepared = profile.PreparedNoChildProfile(
            executable=executable,
            expected_sha256=executable.sha256,
            seatbelt_profile="(version 1)\n",
            evidence=mock.sentinel.compatibility,
        )
        error_read, error_write = os.pipe()
        with (
            mock.patch.object(profile, "require_compatible"),
            mock.patch.object(profile, "_require_live_runtime"),
            mock.patch.object(profile, "_revalidate_prepared_profile"),
            mock.patch.object(
                profile,
                "_fork_with_launch_error_pipe",
                side_effect=_publish_synthetic_launch_receipt(
                    pid=424243,
                    error_read=error_read,
                    error_write=error_write,
                ),
            ),
            mock.patch.object(profile.resource, "getrlimit", return_value=(1, 1)),
            mock.patch.object(profile.os, "getpgid", return_value=424243),
            mock.patch.object(profile.os, "getsid", return_value=424243),
            mock.patch.object(
                profile,
                "process_start_identity",
                side_effect=KeyboardInterrupt("injected binding interrupt"),
            ),
            mock.patch.object(
                profile,
                "_terminate_and_reap",
                side_effect=OSError(errno.EIO, "injected reap failure"),
            ),
            self.assertRaises(profile.NoChildLaunchClosureUnproven) as caught,
        ):
            profile.launch_prepared_no_child_process(
                prepared,
                [executable.path],
                cwd="/",
            )
        self.assertTrue(caught.exception.evidence.exec_acknowledged)
        self.assertTrue(caught.exception.evidence.fork_call_started)
        self.assertTrue(caught.exception.evidence.fork_call_completed)
        self.assertTrue(caught.exception.evidence.pipe_ownership_published)
        self.assertTrue(caught.exception.evidence.leader_receipt_received)
        self.assertFalse(caught.exception.evidence.leader_binding_complete)
        self.assertFalse(caught.exception.evidence.leader_reaped)
        self.assertFalse(caught.exception.evidence.process_group_empty)
        self.assertTrue(caught.exception.evidence.control_pipes_closed)
        self.assertIn(prepared, caught.exception.retained_resources)
        self.assertIn(
            caught.exception.evidence,
            caught.exception.recovery_evidence,
        )

    def test_result_owner_query_interrupt_still_settles_bound_child(self) -> None:
        prepared = _synthetic_prepared_launch()
        error_read, error_write = os.pipe()
        result_owner = _InterruptingLaunchResultOwner()
        with (
            mock.patch.object(profile, "require_compatible"),
            mock.patch.object(profile, "_require_live_runtime"),
            mock.patch.object(profile, "_revalidate_prepared_profile"),
            mock.patch.object(profile, "prove_exec_budget"),
            mock.patch.object(
                profile,
                "_fork_with_launch_error_pipe",
                side_effect=_publish_synthetic_launch_receipt(
                    pid=424244,
                    error_read=error_read,
                    error_write=error_write,
                ),
            ),
            mock.patch.object(profile.resource, "getrlimit", return_value=(1, 1)),
            mock.patch.object(profile.os, "getpgid", return_value=424244),
            mock.patch.object(profile.os, "getsid", return_value=424244),
            mock.patch.object(
                profile,
                "process_start_identity",
                return_value="synthetic-start",
            ),
            mock.patch.object(profile, "_terminate_and_reap") as terminate,
            self.assertRaisesRegex(
                KeyboardInterrupt,
                "ownership query 1",
            ),
        ):
            profile.launch_prepared_no_child_process(
                prepared,
                [prepared.executable.path],
                cwd="/",
                environment={},
                result_owner=result_owner,
            )

        self.assertEqual(result_owner.owns_calls, 2)
        self.assertIsNotNone(result_owner.launched)
        terminate.assert_called_once_with(424244)
        for descriptor in (error_read, error_write):
            with self.assertRaises(OSError) as descriptor_error:
                os.fstat(descriptor)
            self.assertEqual(descriptor_error.exception.errno, errno.EBADF)

    def test_result_owner_query_interrupt_retains_failed_settlement(self) -> None:
        prepared = _synthetic_prepared_launch()
        error_read, error_write = os.pipe()
        result_owner = _InterruptingLaunchResultOwner()
        with (
            mock.patch.object(profile, "require_compatible"),
            mock.patch.object(profile, "_require_live_runtime"),
            mock.patch.object(profile, "_revalidate_prepared_profile"),
            mock.patch.object(profile, "prove_exec_budget"),
            mock.patch.object(
                profile,
                "_fork_with_launch_error_pipe",
                side_effect=_publish_synthetic_launch_receipt(
                    pid=424245,
                    error_read=error_read,
                    error_write=error_write,
                ),
            ),
            mock.patch.object(profile.resource, "getrlimit", return_value=(1, 1)),
            mock.patch.object(profile.os, "getpgid", return_value=424245),
            mock.patch.object(profile.os, "getsid", return_value=424245),
            mock.patch.object(
                profile,
                "process_start_identity",
                return_value="synthetic-start",
            ),
            mock.patch.object(
                profile,
                "_terminate_and_reap",
                side_effect=OSError(errno.EIO, "injected settlement failure"),
            ) as terminate,
            self.assertRaises(profile.NoChildLaunchClosureUnproven) as caught,
        ):
            profile.launch_prepared_no_child_process(
                prepared,
                [prepared.executable.path],
                cwd="/",
                environment={},
                result_owner=result_owner,
            )

        self.assertEqual(result_owner.owns_calls, 2)
        terminate.assert_called_once_with(424245)
        self.assertIn(
            "result-owner-ownership-query:KeyboardInterrupt",
            caught.exception.evidence.reason,
        )
        self.assertFalse(caught.exception.evidence.leader_reaped)
        self.assertFalse(caught.exception.evidence.process_group_empty)
        self.assertIn(result_owner, caught.exception.retained_resources)
        self.assertIn(result_owner.launched, caught.exception.retained_resources)
        for descriptor in (error_read, error_write):
            with self.assertRaises(OSError) as descriptor_error:
                os.fstat(descriptor)
            self.assertEqual(descriptor_error.exception.errno, errno.EBADF)

    def test_live_runtime_uses_only_executable_protected_properties(self) -> None:
        runtime = profile.RuntimeFingerprint(
            platform="darwin",
            system="Darwin",
            macos_product_version="26.5.2",
            macos_build_version="25F84",
            darwin_release="25.5.0",
            python_version=(3, 13, 0),
            python_executable="/synthetic/python3.13",
            effective_uid=501,
        )
        sandbox = profile.ExecutableIdentity(
            path=str(profile.SANDBOX_EXEC),
            device=1,
            inode=2,
            mode=stat.S_IFREG | 0o555,
            uid=0,
            gid=0,
            size=4,
            mtime_ns=1,
            ctime_ns=1,
            sha256="a" * 64,
        )
        probe = replace(sandbox, path="/synthetic/python3.13", inode=3)
        alternate = replace(
            sandbox,
            path="/synthetic/true",
            inode=4,
            sha256="b" * 64,
        )
        evidence = profile.CompatibilityEvidence(
            schema_version=profile.EVIDENCE_SCHEMA_VERSION,
            runtime_pin=profile.PINNED_RUNTIME,
            runtime=runtime,
            sandbox_exec=sandbox,
            probe_executable=probe,
            alternate_executable=alternate,
            seatbelt_profile_sha256="c" * 64,
            parent_nproc_before=(1, 1),
            parent_nproc_after=(1, 1),
            observations=(),
            blockers=(),
        )

        def identities(
            probe_override: profile.ExecutableIdentity,
        ) -> object:
            values = {
                probe.path: probe_override,
                alternate.path: replace(alternate, mtime_ns=11, ctime_ns=12),
            }
            stack = contextlib.ExitStack()
            stack.enter_context(
                mock.patch.object(
                    profile,
                    "_authenticate_root_protected_executable",
                    return_value=_synthetic_probe_attestation(
                        replace(sandbox, mtime_ns=9, ctime_ns=10)
                    ),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    profile,
                    "_read_executable_identity",
                    side_effect=lambda path: values[str(path)],
                )
            )
            return stack

        with (
            mock.patch.object(profile, "_runtime_fingerprint", return_value=runtime),
            identities(replace(probe, mtime_ns=7, ctime_ns=8)),
        ):
            profile._require_live_runtime(evidence)

        for label, changed in (
            ("object", replace(probe, inode=99)),
            ("object-generation", replace(probe, generation=7)),
            ("content", replace(probe, sha256="d" * 64)),
            ("access-policy", replace(probe, mode=stat.S_IFREG | 0o500)),
            (
                "access-flags",
                replace(probe, flags=getattr(stat, "UF_IMMUTABLE", 2)),
            ),
        ):
            with (
                self.subTest(label=label),
                mock.patch.object(
                    profile,
                    "_runtime_fingerprint",
                    return_value=runtime,
                ),
                identities(changed),
                self.assertRaises(profile.NoChildProfileUnavailable) as caught,
            ):
                profile._require_live_runtime(evidence)
            self.assertIn(
                "probe-executable-changed-after-probe",
                caught.exception.evidence.blockers,
            )

    def test_dynamic_loader_environment_injection_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "dynamic-loader"):
            profile._validated_environment(
                {"DYLD_INSERT_LIBRARIES": "/synthetic/injected.dylib"}
            )

    def test_custom_runtime_pin_cannot_prepare_or_launch(self) -> None:
        custom_pin = replace(
            profile.PINNED_RUNTIME,
            macos_product_version="synthetic-probe-only-runtime",
        )
        with (
            mock.patch.object(profile, "probe_compatibility") as probe,
            mock.patch.object(profile, "authenticate_executable") as authenticate,
            self.assertRaisesRegex(profile.NoChildProfileError, "probe-only"),
        ):
            profile.prepare_sandboxed_python_no_child_profile(
                runtime_pin=custom_pin,
            )
        probe.assert_not_called()
        authenticate.assert_not_called()

        prepared = replace(
            _synthetic_prepared_launch(),
            evidence=mock.Mock(production_capable=False),
        )
        with (
            mock.patch.object(profile, "require_compatible"),
            mock.patch.object(profile, "_fork_with_launch_error_pipe") as fork,
            self.assertRaisesRegex(
                profile.NoChildProfileError,
                "exact production runtime pin",
            ),
        ):
            profile.launch_prepared_no_child_process(
                prepared,
                [prepared.executable.path],
                cwd="/",
            )
        fork.assert_not_called()

    def test_sandboxed_python_preparation_binds_path_execution_attestation(
        self,
    ) -> None:
        sandbox_exec = profile.ExecutableIdentity(
            path=str(profile.SANDBOX_EXEC),
            device=1,
            inode=2,
            mode=stat.S_IFREG | 0o555,
            uid=0,
            gid=0,
            size=4,
            mtime_ns=1,
            ctime_ns=1,
            sha256="a" * 64,
        )
        target = replace(
            sandbox_exec,
            path=str(pathlib.Path("/usr/bin/true").resolve(strict=True)),
            inode=3,
            uid=os.geteuid(),
            sha256="b" * 64,
        )
        target_attestation = profile.PathExecutedExecutableAttestation(
            executable=target,
            components=(),
        )
        evidence = mock.Mock()
        evidence.runtime_pin.sandbox_exec_sha256 = sandbox_exec.sha256
        runtime_pin = profile.PINNED_RUNTIME
        with (
            mock.patch.object(
                profile,
                "probe_compatibility",
                return_value=evidence,
            ) as probe_compatibility,
            mock.patch.object(profile, "require_compatible"),
            mock.patch.object(
                profile,
                "authenticate_executable",
                return_value=sandbox_exec,
            ) as authenticate_loader,
            mock.patch.object(
                profile,
                "python_runtime_executable",
                return_value=pathlib.Path(target.path),
            ),
            mock.patch.object(
                profile,
                "_authenticate_path_executed_executable",
                return_value=target_attestation,
            ) as authenticate_target,
        ):
            prepared = profile.prepare_sandboxed_python_no_child_profile(
                additional_seatbelt_rules="(deny file-write*)",
                runtime_pin=runtime_pin,
            )

        authenticate_loader.assert_called_once_with(
            profile.SANDBOX_EXEC,
            expected_sha256=sandbox_exec.sha256,
        )
        probe_compatibility.assert_called_once_with(pin=runtime_pin)
        authenticate_target.assert_called_once_with(pathlib.Path(target.path))
        self.assertEqual(prepared.sandboxed_target, target)
        self.assertIs(
            prepared.sandboxed_target_attestation,
            target_attestation,
        )
        with (
            mock.patch.object(
                profile,
                "authenticate_executable",
                return_value=sandbox_exec,
            ),
            self.assertRaisesRegex(
                profile.NoChildProfileError,
                "missing its path-execution attestation",
            ),
        ):
            profile._revalidate_prepared_profile(
                replace(prepared, sandboxed_target_attestation=None)
            )

    @unittest.skipUnless(
        sys.platform == "darwin" and sys.version_info[:2] == (3, 13),
        "Darwin with Python 3.13 is required",
    )
    def test_sandboxed_python_write_authority_is_fd_bound_and_default_deny(
        self,
    ) -> None:
        sandbox_exec = profile.ExecutableIdentity(
            path=str(profile.SANDBOX_EXEC),
            device=1,
            inode=2,
            mode=stat.S_IFREG | 0o555,
            uid=0,
            gid=0,
            size=4,
            mtime_ns=1,
            ctime_ns=1,
            sha256="a" * 64,
        )
        target = replace(
            sandbox_exec,
            path=str(pathlib.Path("/usr/bin/true").resolve(strict=True)),
            inode=3,
            uid=os.geteuid(),
            sha256="b" * 64,
        )
        target_attestation = profile.PathExecutedExecutableAttestation(
            executable=target,
            components=(),
        )
        evidence = mock.Mock()
        evidence.runtime_pin.sandbox_exec_sha256 = sandbox_exec.sha256
        runtime_pin = profile.PINNED_RUNTIME
        with owned_temporary_directory("sandboxed-python-writable-root-") as root:
            writable_path = root / "runtime"
            writable_path.mkdir(mode=0o700)
            writable_fd = os.open(
                writable_path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                writable = profile.attest_writable_root(
                    writable_path,
                    directory_fd=writable_fd,
                )
                writable_key = (
                    writable.identity.device,
                    writable.identity.inode,
                )
                with self.assertRaisesRegex(
                    profile.ExecutableAuthenticationError,
                    "overlaps the sandboxed target through a path alias",
                ):
                    profile._validated_sandboxed_writable_roots(
                        (writable,),
                        protected_component_keys=frozenset({writable_key}),
                    )
                with (
                    mock.patch.object(
                        profile,
                        "probe_compatibility",
                        return_value=evidence,
                    ),
                    mock.patch.object(profile, "require_compatible"),
                    mock.patch.object(
                        profile,
                        "authenticate_executable",
                        return_value=sandbox_exec,
                    ),
                    mock.patch.object(
                        profile,
                        "python_runtime_executable",
                        return_value=pathlib.Path(target.path),
                    ),
                    mock.patch.object(
                        profile,
                        "_authenticate_path_executed_executable",
                        return_value=target_attestation,
                    ),
                    self.assertRaisesRegex(
                        profile.NoChildProfileError,
                        "default-deny filesystem writes",
                    ),
                ):
                    profile.prepare_sandboxed_python_no_child_profile(
                        runtime_pin=runtime_pin,
                        writable_roots=(writable,),
                    )

                with (
                    mock.patch.object(
                        profile,
                        "probe_compatibility",
                        return_value=evidence,
                    ),
                    mock.patch.object(profile, "require_compatible"),
                    mock.patch.object(
                        profile,
                        "authenticate_executable",
                        return_value=sandbox_exec,
                    ),
                    mock.patch.object(
                        profile,
                        "python_runtime_executable",
                        return_value=pathlib.Path(target.path),
                    ),
                    mock.patch.object(
                        profile,
                        "_authenticate_path_executed_executable",
                        return_value=target_attestation,
                    ),
                ):
                    prepared = profile.prepare_sandboxed_python_no_child_profile(
                        additional_seatbelt_rules="(deny file-write*)",
                        runtime_pin=runtime_pin,
                        writable_roots=(writable,),
                    )

                lines = prepared.seatbelt_profile.splitlines()
                allow_rule = f'(allow file-write* (subpath "{writable_path}"))'
                self.assertEqual(prepared.writable_roots, (writable,))
                self.assertEqual(
                    prepared.writable_roots[0].path_components[-1].path,
                    str(writable_path),
                )
                self.assertIn("(deny file-write*)", lines)
                self.assertIn("(deny file-link)", lines)
                self.assertIn(allow_rule, lines)
                self.assertLess(
                    lines.index("(deny file-write*)"),
                    lines.index(allow_rule),
                )
                self.assertLess(
                    lines.index("(deny file-link)"), lines.index(allow_rule)
                )
                with (
                    mock.patch.object(profile, "require_compatible"),
                    mock.patch.object(profile, "_require_live_runtime"),
                    mock.patch.object(profile.os, "fork") as fork,
                    self.assertRaisesRegex(
                        ValueError,
                        "writable-root descriptors cannot be inherited",
                    ),
                ):
                    profile.launch_prepared_no_child_process(
                        prepared,
                        [target.path],
                        cwd=root,
                        pass_fds=(writable_fd,),
                    )
                fork.assert_not_called()

                root.chmod(0o777)
                try:
                    with self.assertRaisesRegex(
                        profile.ExecutableAuthenticationError,
                        "ancestor permits an untrusted writer|access policy",
                    ):
                        profile._validated_sandboxed_writable_roots(
                            (writable,),
                            protected_component_keys=frozenset({(999, 999)}),
                        )
                finally:
                    root.chmod(0o700)
            finally:
                os.close(writable_fd)

            unsafe_ancestor = root / "unsafe-ancestor"
            unsafe_ancestor.mkdir(mode=0o700)
            unsafe_runtime = unsafe_ancestor / "runtime"
            unsafe_runtime.mkdir(mode=0o700)
            unsafe_fd = os.open(
                unsafe_runtime,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            unsafe_ancestor.chmod(0o777)
            try:
                with self.assertRaisesRegex(
                    profile.ExecutableAuthenticationError,
                    "ancestor permits an untrusted writer",
                ):
                    profile.attest_writable_root(
                        unsafe_runtime,
                        directory_fd=unsafe_fd,
                    )
            finally:
                unsafe_ancestor.chmod(0o700)
                os.close(unsafe_fd)

    def test_path_executed_target_rejects_untrusted_owner_or_writer(
        self,
    ) -> None:
        clear_metadata = ExtendedMetadataEvidence(0, (), False)
        with owned_temporary_directory("path-target-policy-") as temporary:
            root = temporary.resolve(strict=True)
            root.chmod(0o700)
            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o755)
            target = unsafe / "python3.13"
            _write_synthetic_macho(target)
            unsafe.chmod(0o777)
            try:
                with (
                    mock.patch.object(
                        profile,
                        "verify_macos_filesystem_metadata",
                        return_value=clear_metadata,
                    ),
                    self.assertRaisesRegex(
                        profile.ExecutableAuthenticationError,
                        "access policy permits an untrusted writer",
                    ),
                ):
                    profile._authenticate_path_executed_executable(target)
            finally:
                unsafe.chmod(0o755)

        with owned_temporary_directory("path-target-owner-") as temporary:
            root = temporary.resolve(strict=True)
            root.chmod(0o700)
            target = root / "python3.13"
            _write_synthetic_macho(target)
            with (
                mock.patch.object(
                    profile,
                    "verify_macos_filesystem_metadata",
                    return_value=clear_metadata,
                ),
                mock.patch.object(
                    profile.os,
                    "geteuid",
                    return_value=os.geteuid() + 1,
                ),
                self.assertRaisesRegex(
                    profile.ExecutableAuthenticationError,
                    "access policy has an untrusted owner",
                ),
            ):
                profile._authenticate_path_executed_executable(target)

    def test_path_target_revalidation_distinguishes_protected_properties(
        self,
    ) -> None:
        clear_metadata = ExtendedMetadataEvidence(0, (), False)
        cases = (
            (
                "object-identity",
                "object identity changed after preparation",
            ),
            ("content", "content changed after preparation"),
            ("access-policy", "access policy"),
        )
        for mutation, message in cases:
            with (
                self.subTest(mutation=mutation),
                owned_temporary_directory(f"path-target-{mutation}-") as temporary,
            ):
                root = temporary.resolve(strict=True)
                root.chmod(0o700)
                runtime = root / "runtime"
                runtime.mkdir(mode=0o755)
                target = runtime / "python3.13"
                _write_synthetic_macho(target)
                with mock.patch.object(
                    profile,
                    "verify_macos_filesystem_metadata",
                    return_value=clear_metadata,
                ):
                    attestation = profile._authenticate_path_executed_executable(target)
                    if mutation == "object-identity":
                        replacement = runtime / "replacement"
                        _write_synthetic_macho(replacement)
                        os.replace(replacement, target)
                    elif mutation == "content":
                        _write_synthetic_macho(target, alternate=True)
                    else:
                        runtime.chmod(0o775)
                    try:
                        with self.assertRaisesRegex(
                            profile.ExecutableAuthenticationError,
                            message,
                        ):
                            profile._revalidate_path_executed_executable(attestation)
                    finally:
                        runtime.chmod(0o755)

    def test_root_protected_executable_rejects_component_acl(self) -> None:
        executable = profile.ExecutableIdentity(
            path="/usr/bin/true",
            device=1,
            inode=4,
            mode=stat.S_IFREG | 0o555,
            uid=0,
            gid=0,
            size=4,
            mtime_ns=1,
            ctime_ns=1,
            sha256="a" * 64,
        )
        clear = ExtendedMetadataEvidence(0, (), False)
        acl = ExtendedMetadataEvidence(
            1,
            (),
            False,
            ("user:fixture:allow:write",),
        )

        def component(
            path: str,
            *,
            kind: str,
            inode: int,
            metadata: ExtendedMetadataEvidence,
        ) -> PathComponentEvidence:
            return PathComponentEvidence(
                path=path,
                kind=kind,
                identity=NodeIdentity(
                    device=1,
                    inode=inode,
                    mode=(
                        stat.S_IFREG | 0o555 if kind == "file" else stat.S_IFDIR | 0o555
                    ),
                    link_count=1 if kind == "file" else 2,
                    uid=0,
                    gid=0,
                    size=4 if kind == "file" else 0,
                    mtime_ns=1,
                    ctime_ns=1,
                    flags=0,
                    generation=0,
                ),
                extended_metadata=metadata,
            )

        clear_components = (
            component("/", kind="directory", inode=1, metadata=clear),
            component("/usr", kind="directory", inode=2, metadata=clear),
            component("/usr/bin", kind="directory", inode=3, metadata=clear),
            component("/usr/bin/true", kind="file", inode=4, metadata=clear),
        )
        for acl_index in range(len(clear_components)):
            with self.subTest(acl_component=clear_components[acl_index].path):
                components = list(clear_components)
                components[acl_index] = replace(
                    components[acl_index],
                    extended_metadata=acl,
                )
                attestation = profile.PathExecutedExecutableAttestation(
                    executable=executable,
                    components=tuple(components),
                )
                with (
                    mock.patch.object(
                        profile,
                        "_authenticate_path_executed_executable",
                        return_value=attestation,
                    ),
                    self.assertRaisesRegex(
                        profile.ExecutableAuthenticationError,
                        "extended ACL",
                    ),
                ):
                    profile.authenticate_executable(
                        executable.path,
                        expected_sha256=executable.sha256,
                    )

    def test_root_protected_executable_rejects_non_root_component(self) -> None:
        executable, _ = _synthetic_probe_identities()
        clear = ExtendedMetadataEvidence(0, (), False)

        def directory(path: str, *, inode: int, uid: int) -> PathComponentEvidence:
            return PathComponentEvidence(
                path=path,
                kind="directory",
                identity=NodeIdentity(
                    device=1,
                    inode=inode,
                    mode=stat.S_IFDIR | 0o555,
                    link_count=2,
                    uid=uid,
                    gid=0,
                    size=0,
                    mtime_ns=1,
                    ctime_ns=1,
                    flags=0,
                    generation=0,
                ),
                extended_metadata=clear,
            )

        leaf = PathComponentEvidence(
            path=executable.path,
            kind="file",
            identity=NodeIdentity(
                device=1,
                inode=executable.inode,
                mode=executable.mode,
                link_count=1,
                uid=executable.uid,
                gid=executable.gid,
                size=executable.size,
                mtime_ns=executable.mtime_ns,
                ctime_ns=executable.ctime_ns,
                flags=executable.flags,
                generation=executable.generation,
            ),
            extended_metadata=clear,
        )
        attestation = profile.PathExecutedExecutableAttestation(
            executable=executable,
            components=(
                directory("/", inode=10, uid=0),
                directory("/synthetic", inode=11, uid=max(1, os.geteuid())),
                leaf,
            ),
        )
        with (
            mock.patch.object(
                profile,
                "_authenticate_path_executed_executable",
                return_value=attestation,
            ),
            self.assertRaisesRegex(
                profile.ExecutableAuthenticationError,
                "root-owned and immutable",
            ),
        ):
            profile._authenticate_root_protected_executable(executable.path)

    def test_root_protected_executable_rejects_root_runtime(self) -> None:
        executable, _ = _synthetic_probe_identities()
        with (
            mock.patch.object(profile.os, "geteuid", return_value=0),
            mock.patch.object(
                profile,
                "_authenticate_path_executed_executable",
                return_value=_synthetic_probe_attestation(executable),
            ),
            self.assertRaisesRegex(
                profile.ExecutableAuthenticationError,
                "root execution is outside",
            ),
        ):
            profile._authenticate_root_protected_executable(executable.path)

    def test_generic_executable_reads_use_path_attestation(self) -> None:
        executable, _ = _synthetic_probe_identities()
        attestation = _synthetic_probe_attestation(executable)
        with mock.patch.object(
            profile,
            "_authenticate_path_executed_executable",
            return_value=attestation,
        ) as authenticate:
            observed = profile._read_executable_identity(executable.path)
        authenticate.assert_called_once_with(executable.path)
        self.assertIs(observed, executable)

    def test_launch_budgets_exact_sandbox_argv_before_fork(self) -> None:
        executable = profile.ExecutableIdentity(
            path="/synthetic/app-server",
            device=1,
            inode=2,
            mode=0o100755,
            uid=os.getuid(),
            gid=os.getgid(),
            size=4,
            mtime_ns=1,
            ctime_ns=1,
            sha256="a" * 64,
        )
        prepared = profile.PreparedNoChildProfile(
            executable=executable,
            expected_sha256=executable.sha256,
            seatbelt_profile="(version 1)\n(deny default)\n",
            evidence=mock.sentinel.compatibility,
        )
        environment = {"PATH": "/usr/bin", "LANG": "C"}
        expected_argv = (
            str(profile.SANDBOX_EXEC),
            "-p",
            prepared.seatbelt_profile,
            executable.path,
            "app-server",
        )
        with (
            mock.patch.object(profile, "require_compatible"),
            mock.patch.object(profile, "_require_live_runtime"),
            mock.patch.object(profile, "_revalidate_prepared_profile"),
            mock.patch.object(
                profile,
                "prove_exec_budget",
                side_effect=ValueError("synthetic exec budget overflow"),
            ) as budget,
            mock.patch.object(profile, "_fork_with_launch_error_pipe") as fork,
            self.assertRaisesRegex(ValueError, "exec budget overflow"),
        ):
            profile.launch_prepared_no_child_process(
                prepared,
                [executable.path, "app-server"],
                cwd="/",
                environment=environment,
            )
        budget.assert_called_once_with(expected_argv, environment=environment)
        fork.assert_not_called()

    def test_sandboxed_python_target_uses_one_authenticated_sandbox_wrapper(
        self,
    ) -> None:
        sandbox_exec = profile.ExecutableIdentity(
            path=str(profile.SANDBOX_EXEC),
            device=1,
            inode=2,
            mode=0o100755,
            uid=0,
            gid=0,
            size=4,
            mtime_ns=1,
            ctime_ns=1,
            sha256="a" * 64,
        )
        target = profile.ExecutableIdentity(
            path="/synthetic/python3.13",
            device=3,
            inode=4,
            mode=0o100755,
            uid=os.getuid(),
            gid=os.getgid(),
            size=4,
            mtime_ns=1,
            ctime_ns=1,
            sha256="b" * 64,
        )
        prepared = profile.PreparedNoChildProfile(
            executable=sandbox_exec,
            expected_sha256=sandbox_exec.sha256,
            seatbelt_profile="(version 1)\n(deny process-fork)\n",
            evidence=mock.sentinel.compatibility,
            sandboxed_target=target,
        )
        environment = {"PATH": "/usr/bin", "LANG": "C"}
        expected_argv = (
            str(profile.SANDBOX_EXEC),
            "-p",
            prepared.seatbelt_profile,
            target.path,
            "-I",
            "-S",
        )
        with (
            mock.patch.object(profile, "require_compatible"),
            mock.patch.object(profile, "_require_live_runtime"),
            mock.patch.object(profile, "_revalidate_prepared_profile"),
            mock.patch.object(
                profile,
                "prove_exec_budget",
                side_effect=ValueError("synthetic exec budget overflow"),
            ) as budget,
            mock.patch.object(profile, "_fork_with_launch_error_pipe") as fork,
            self.assertRaisesRegex(ValueError, "exec budget overflow"),
        ):
            profile.launch_prepared_no_child_process(
                prepared,
                [target.path, "-I", "-S"],
                cwd="/",
                environment=environment,
            )
        budget.assert_called_once_with(expected_argv, environment=environment)
        fork.assert_not_called()

    def test_unsupported_platform_blocks_without_starting_probe_children(
        self,
    ) -> None:
        runtime = profile.RuntimeFingerprint(
            platform="linux",
            system="Linux",
            macos_product_version=None,
            macos_build_version=None,
            darwin_release=None,
            python_version=(3, 13, 0),
            python_executable="/synthetic/python3.13",
            effective_uid=1000,
        )
        with (
            mock.patch.object(profile, "_runtime_fingerprint", return_value=runtime),
            mock.patch.object(profile, "_run_probe_case") as run_probe,
        ):
            evidence = profile.probe_compatibility()

        self.assertFalse(evidence.compatible)
        self.assertEqual(evidence.blockers, ("unsupported-platform",))
        self.assertEqual(evidence.observations, ())
        run_probe.assert_not_called()
        with self.assertRaises(profile.NoChildProfileUnavailable) as raised:
            profile.require_compatible(evidence)
        self.assertEqual(raised.exception.evidence.runtime, evidence.runtime)
        self.assertIn(
            "unsupported-platform",
            raised.exception.evidence.blockers,
        )
        synthetic_identity = profile.ExecutableIdentity(
            path="/synthetic/app-server",
            device=1,
            inode=2,
            mode=0o100755,
            uid=0,
            gid=0,
            size=4,
            mtime_ns=1,
            ctime_ns=1,
            sha256="a" * 64,
        )
        prepared = profile.PreparedNoChildProfile(
            executable=synthetic_identity,
            expected_sha256="a" * 64,
            seatbelt_profile="synthetic",
            evidence=evidence,
        )
        with (
            mock.patch.object(profile.os, "fork") as fork,
            self.assertRaises(profile.NoChildProfileUnavailable),
        ):
            profile.launch_prepared_no_child_process(
                prepared,
                [synthetic_identity.path],
                cwd="/",
            )
        fork.assert_not_called()

    def test_probe_attestation_failure_precedes_first_compatibility_exec(
        self,
    ) -> None:
        probe_path = pathlib.Path("/synthetic/python3.13")
        runtime = profile.RuntimeFingerprint(
            platform="darwin",
            system="Darwin",
            macos_product_version=profile.PINNED_RUNTIME.macos_product_version,
            macos_build_version=profile.PINNED_RUNTIME.macos_build_version,
            darwin_release=profile.PINNED_RUNTIME.darwin_release,
            python_version=(3, 13, 0),
            python_executable=str(probe_path),
            effective_uid=501,
        )
        sandbox_exec = profile.ExecutableIdentity(
            path=str(profile.SANDBOX_EXEC),
            device=1,
            inode=2,
            mode=stat.S_IFREG | 0o555,
            uid=0,
            gid=0,
            size=4,
            mtime_ns=1,
            ctime_ns=1,
            sha256=profile.PINNED_RUNTIME.sandbox_exec_sha256,
        )
        attestation_error = profile.ExecutableAuthenticationError(
            "synthetic path access policy failure"
        )
        with (
            mock.patch.object(profile, "_runtime_fingerprint", return_value=runtime),
            mock.patch.object(
                profile,
                "_authenticate_root_protected_executable",
                return_value=_synthetic_probe_attestation(sandbox_exec),
            ),
            mock.patch.object(
                profile,
                "_authenticate_path_executed_executable",
                side_effect=attestation_error,
            ) as authenticate_path,
            mock.patch.object(profile, "_run_probe_case") as run_probe,
            mock.patch.object(
                profile,
                "_spawn_owned_probe_process",
            ) as spawn_probe,
        ):
            evidence = profile.probe_compatibility(
                probe_executable_path=probe_path,
            )

        authenticate_path.assert_called_once_with(probe_path)
        run_probe.assert_not_called()
        spawn_probe.assert_not_called()
        self.assertIsNone(evidence.probe_executable)
        self.assertTrue(
            any(
                blocker.startswith(
                    "probe-setup-failed:synthetic path access policy failure"
                )
                for blocker in evidence.blockers
            )
        )

    def test_sandbox_root_authentication_failure_precedes_probe_exec(self) -> None:
        runtime = profile.RuntimeFingerprint(
            platform="darwin",
            system="Darwin",
            macos_product_version=profile.PINNED_RUNTIME.macos_product_version,
            macos_build_version=profile.PINNED_RUNTIME.macos_build_version,
            darwin_release=profile.PINNED_RUNTIME.darwin_release,
            python_version=(3, 13, 0),
            python_executable="/synthetic/python3.13",
            effective_uid=501,
        )
        with (
            mock.patch.object(profile, "_runtime_fingerprint", return_value=runtime),
            mock.patch.object(
                profile,
                "_authenticate_root_protected_executable",
                side_effect=profile.ExecutableAuthenticationError(
                    "synthetic root-path ACL"
                ),
            ) as authenticate_root,
            mock.patch.object(
                profile,
                "_authenticate_path_executed_executable",
            ) as authenticate_probe,
            mock.patch.object(profile, "_run_probe_case") as run_probe,
        ):
            evidence = profile.probe_compatibility()

        authenticate_root.assert_called_once_with(profile.SANDBOX_EXEC)
        authenticate_probe.assert_not_called()
        run_probe.assert_not_called()
        self.assertIn("sandbox-exec-unavailable", evidence.blockers)

    def test_live_runtime_rejects_failed_sandbox_root_revalidation(self) -> None:
        runtime = profile.RuntimeFingerprint(
            platform="darwin",
            system="Darwin",
            macos_product_version=profile.PINNED_RUNTIME.macos_product_version,
            macos_build_version=profile.PINNED_RUNTIME.macos_build_version,
            darwin_release=profile.PINNED_RUNTIME.darwin_release,
            python_version=(3, 13, 0),
            python_executable="/synthetic/python3.13",
            effective_uid=501,
        )
        sandbox_exec = profile.ExecutableIdentity(
            path=str(profile.SANDBOX_EXEC),
            device=1,
            inode=2,
            mode=stat.S_IFREG | 0o555,
            uid=0,
            gid=0,
            size=4,
            mtime_ns=1,
            ctime_ns=1,
            sha256=profile.PINNED_RUNTIME.sandbox_exec_sha256,
        )
        evidence = profile.CompatibilityEvidence(
            schema_version=profile.EVIDENCE_SCHEMA_VERSION,
            runtime_pin=profile.PINNED_RUNTIME,
            runtime=runtime,
            sandbox_exec=sandbox_exec,
            probe_executable=None,
            alternate_executable=None,
            seatbelt_profile_sha256=None,
            parent_nproc_before=None,
            parent_nproc_after=None,
            observations=(),
            blockers=(),
        )
        with (
            mock.patch.object(profile, "_runtime_fingerprint", return_value=runtime),
            mock.patch.object(
                profile,
                "_authenticate_root_protected_executable",
                side_effect=profile.ExecutableAuthenticationError(
                    "synthetic root-path ACL"
                ),
            ),
            mock.patch.object(profile, "_read_executable_identity") as read_generic,
            self.assertRaises(profile.NoChildProfileUnavailable) as caught,
        ):
            profile._require_live_runtime(evidence)

        read_generic.assert_not_called()
        self.assertIn(
            "sandbox-exec-revalidation-failed-after-probe",
            caught.exception.evidence.blockers,
        )

    def test_ambiguous_observation_cannot_be_hidden_by_empty_blockers(self) -> None:
        runtime = profile.RuntimeFingerprint(
            platform="darwin",
            system="Darwin",
            macos_product_version=profile.PINNED_RUNTIME.macos_product_version,
            macos_build_version=profile.PINNED_RUNTIME.macos_build_version,
            darwin_release=profile.PINNED_RUNTIME.darwin_release,
            python_version=(3, 13, 0),
            python_executable="/synthetic/python3.13",
            effective_uid=501,
        )
        sandbox_exec = profile.ExecutableIdentity(
            path=str(profile.SANDBOX_EXEC),
            device=1,
            inode=2,
            mode=0o100755,
            uid=0,
            gid=0,
            size=4,
            mtime_ns=1,
            ctime_ns=1,
            sha256=profile.PINNED_RUNTIME.sandbox_exec_sha256,
        )
        seatbelt = profile.build_seatbelt_profile(sandbox_exec.path)
        profile_sha256 = hashlib.sha256(seatbelt.encode("utf-8")).hexdigest()
        observations = _synthetic_compatible_observations(
            profile_sha256=profile_sha256,
            parent_limit=(2666, 4000),
        )
        fork_index = next(
            index
            for index, item in enumerate(observations)
            if item.layer == "combined" and item.action == "fork"
        )
        observations[fork_index] = replace(
            observations[fork_index],
            outcome="ambiguous",
            error_number=None,
            detail="synthetic malformed child result",
        )
        evidence = profile.CompatibilityEvidence(
            schema_version=profile.EVIDENCE_SCHEMA_VERSION,
            runtime_pin=profile.PINNED_RUNTIME,
            runtime=runtime,
            sandbox_exec=sandbox_exec,
            probe_executable=sandbox_exec,
            alternate_executable=sandbox_exec,
            seatbelt_profile_sha256=profile_sha256,
            parent_nproc_before=(2666, 4000),
            parent_nproc_after=(2666, 4000),
            observations=tuple(observations),
            blockers=(),
        )

        with self.assertRaises(profile.NoChildProfileUnavailable) as raised:
            profile.require_compatible(evidence)

        self.assertIn("combined-fork-not-denied", raised.exception.evidence.blockers)
        self.assertIn(
            "ambiguous-combined-fork",
            raised.exception.evidence.blockers,
        )

    def test_unpinned_macos_and_python_runtime_block_before_probe(self) -> None:
        runtime = profile.RuntimeFingerprint(
            platform="darwin",
            system="Darwin",
            macos_product_version="99.0",
            macos_build_version="99Z999",
            darwin_release="99.0.0",
            python_version=(3, 12, 9),
            python_executable="/synthetic/python3.12",
            effective_uid=501,
        )
        sandbox_exec = profile.ExecutableIdentity(
            path=str(profile.SANDBOX_EXEC),
            device=1,
            inode=2,
            mode=0o100755,
            uid=0,
            gid=0,
            size=4,
            mtime_ns=1,
            ctime_ns=1,
            sha256=profile.PINNED_RUNTIME.sandbox_exec_sha256,
        )
        with (
            mock.patch.object(profile, "_runtime_fingerprint", return_value=runtime),
            mock.patch.object(
                profile,
                "_authenticate_root_protected_executable",
                return_value=_synthetic_probe_attestation(sandbox_exec),
            ),
            mock.patch.object(profile, "_run_probe_case") as run_probe,
        ):
            evidence = profile.probe_compatibility()

        self.assertFalse(evidence.compatible)
        self.assertIn("unsupported-python-runtime", evidence.blockers)
        self.assertIn("unapproved-macos-product-version", evidence.blockers)
        self.assertIn("unapproved-macos-build-version", evidence.blockers)
        self.assertIn("unapproved-darwin-release", evidence.blockers)
        run_probe.assert_not_called()

    @unittest.skipUnless(sys.platform == "darwin", "Mach-O policy is Darwin-only")
    def test_writable_synthetic_target_cannot_be_authenticated_for_production(
        self,
    ) -> None:
        with owned_temporary_directory("no-child-auth-") as temporary:
            synthetic = temporary / "synthetic-app-server"
            shutil.copyfile(pathlib.Path(sys.executable).resolve(), synthetic)
            synthetic.chmod(0o755)

            with self.assertRaisesRegex(
                profile.ExecutableAuthenticationError,
                "root-owned and immutable",
            ):
                profile.authenticate_executable(
                    synthetic,
                    expected_sha256=_sha256(synthetic),
                )

    def test_incompatible_evidence_blocks_prepare_before_authentication(self) -> None:
        runtime = profile.RuntimeFingerprint(
            platform="linux",
            system="Linux",
            macos_product_version=None,
            macos_build_version=None,
            darwin_release=None,
            python_version=(3, 13, 0),
            python_executable="/synthetic/python3.13",
            effective_uid=1000,
        )
        evidence = profile.CompatibilityEvidence(
            schema_version=profile.EVIDENCE_SCHEMA_VERSION,
            runtime_pin=profile.PINNED_RUNTIME,
            runtime=runtime,
            sandbox_exec=None,
            probe_executable=None,
            alternate_executable=None,
            seatbelt_profile_sha256=None,
            parent_nproc_before=None,
            parent_nproc_after=None,
            observations=(),
            blockers=("unsupported-platform",),
        )
        with (
            mock.patch.object(
                profile,
                "probe_compatibility",
                return_value=evidence,
            ),
            mock.patch.object(profile, "authenticate_executable") as authenticate,
            self.assertRaises(profile.NoChildProfileUnavailable) as raised,
        ):
            profile.prepare_no_child_profile(
                "/synthetic/app-server",
                expected_sha256="a" * 64,
            )

        authenticate.assert_not_called()
        self.assertEqual(raised.exception.evidence.runtime, evidence.runtime)
        self.assertIn(
            "unsupported-platform",
            raised.exception.evidence.blockers,
        )


class NoChildProfileDarwinIntegrationTests(unittest.TestCase):
    RUNTIME_PIN = profile.PINNED_RUNTIME
    EXPECTED_MACHINE: str | None = None
    PRODUCTION_EVIDENCE_EXPECTED = True

    @classmethod
    def _skip_or_fail(cls, message: str) -> None:
        if os.environ.get(REQUIRE_LIVE_NO_CHILD_PROFILE_ENV) == "1":
            raise AssertionError(
                f"required live no-child profile check cannot skip: {message}"
            )
        raise unittest.SkipTest(message)

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        runtime = profile._runtime_fingerprint()
        pin = cls.RUNTIME_PIN
        cls._runtime_pin = pin
        if cls.EXPECTED_MACHINE is not None:
            observed_machine = platform.machine()
            if observed_machine != cls.EXPECTED_MACHINE:
                cls._skip_or_fail(
                    "live no-child profile checks require the exact machine "
                    f"architecture: observed={observed_machine!r}, "
                    f"pinned={cls.EXPECTED_MACHINE!r}"
                )
        observed_runtime = (
            runtime.platform,
            runtime.python_version[:2],
            runtime.macos_product_version,
            runtime.macos_build_version,
            runtime.darwin_release,
        )
        pinned_runtime = (
            "darwin",
            (pin.python_major, pin.python_minor),
            pin.macos_product_version,
            pin.macos_build_version,
            pin.darwin_release,
        )
        if observed_runtime != pinned_runtime:
            message = (
                "live no-child profile checks require the exact pinned macOS runtime: "
                f"observed={observed_runtime!r}, pinned={pinned_runtime!r}"
            )
            cls._skip_or_fail(message)
        cls._parent_limit_before = resource.getrlimit(resource.RLIMIT_NPROC)
        cls._temporary = contextlib.ExitStack()
        cls.addClassCleanup(cls._temporary.close)
        root = cls._temporary.enter_context(
            owned_temporary_directory("no-child-probe-")
        )
        cls.synthetic_python = root / "synthetic-python3.13"
        cls.synthetic_alternate = root / "synthetic-alternate"
        shutil.copyfile(profile.python_runtime_executable(), cls.synthetic_python)
        shutil.copyfile(pathlib.Path("/usr/bin/true"), cls.synthetic_alternate)
        cls.synthetic_python.chmod(0o755)
        cls.synthetic_alternate.chmod(0o755)
        cls.evidence = profile.probe_compatibility(
            pin=pin,
            probe_executable_path=cls.synthetic_python,
            alternate_executable_path=cls.synthetic_alternate,
            python_home=sys.base_prefix,
        )

    def _assert_ordered_leader_binding(
        self,
        observation: profile.ProbeObservation,
    ) -> None:
        expected_limit = (
            self._parent_limit_before if observation.layer == "seatbelt" else (0, 0)
        )
        expected_profile = (
            None
            if observation.layer == "rlimit"
            else self.evidence.seatbelt_profile_sha256
        )
        self.assertTrue(observation.pre_exec_setsid_succeeded)
        self.assertEqual(
            observation.pre_exec_pid,
            observation.pre_exec_process_group,
        )
        self.assertEqual(observation.pre_exec_pid, observation.pre_exec_session)
        self.assertEqual(observation.child_pid, observation.pre_exec_pid)
        self.assertEqual(observation.child_process_group, observation.child_pid)
        self.assertEqual(observation.child_session, observation.child_pid)
        self.assertTrue(observation.child_start_identity)
        self.assertEqual(observation.profile_sha256, expected_profile)
        self.assertEqual(
            (
                observation.pre_exec_nproc_soft,
                observation.pre_exec_nproc_hard,
            ),
            expected_limit,
        )
        self.assertEqual(
            (observation.nproc_soft, observation.nproc_hard),
            expected_limit,
        )

    def test_probe_uses_exact_synthetic_macho_executables(self) -> None:
        self.assertEqual(self.evidence.runtime_pin, self._runtime_pin)
        self.assertIsNotNone(self.evidence.probe_executable)
        assert self.evidence.probe_executable is not None
        self.assertEqual(
            self.evidence.probe_executable.path,
            str(self.synthetic_python),
        )
        self.assertIsNotNone(self.evidence.alternate_executable)
        assert self.evidence.alternate_executable is not None
        self.assertEqual(
            self.evidence.alternate_executable.path,
            str(self.synthetic_alternate),
        )
        seatbelt = profile.build_seatbelt_profile(self.synthetic_python)
        self.assertIn(str(self.synthetic_python), seatbelt)
        self.assertNotIn(str(self.synthetic_alternate), seatbelt)
        self.assertEqual(
            json.loads(json.dumps(self.evidence.to_json())),
            self.evidence.to_json(),
        )
        protected = pathlib.Path("/usr/bin/true")
        authenticated = profile.authenticate_executable(
            protected,
            expected_sha256=_sha256(protected),
        )
        self.assertEqual(authenticated.path, str(protected))

    def test_every_probe_preserves_the_ordered_launch_binding(self) -> None:
        self.assertEqual(len(self.evidence.observations), 24)
        for observation in self.evidence.observations:
            with self.subTest(
                layer=observation.layer,
                action=observation.action,
            ):
                self._assert_ordered_leader_binding(observation)

    def test_rlimit_zero_denies_every_creation_api_and_spares_parent(self) -> None:
        if self.evidence.parent_nproc_before is None:
            self._skip_or_fail("runtime pin did not admit the Darwin probe")
        self.assertEqual(
            self.evidence.parent_nproc_before,
            self._parent_limit_before,
        )
        self.assertEqual(
            self.evidence.parent_nproc_after,
            self._parent_limit_before,
        )
        self.assertEqual(
            resource.getrlimit(resource.RLIMIT_NPROC),
            self._parent_limit_before,
        )
        for action in ("fork", "posix_spawn", "popen", "double_fork"):
            with self.subTest(action=action):
                observation = self.evidence.observation("rlimit", action)
                self.assertIsNotNone(observation)
                assert observation is not None
                self.assertEqual(observation.outcome, "denied")
                self.assertEqual(observation.error_number, errno.EAGAIN)
                self.assertNotEqual(observation.child_pid, os.getpid())
                self.assertEqual(
                    (observation.nproc_soft, observation.nproc_hard),
                    (0, 0),
                )
        for action in ("setsid", "setpgid"):
            observation = self.evidence.observation("rlimit", action)
            self.assertIsNotNone(observation)
            assert observation is not None
            self.assertEqual(observation.outcome, "denied")
            self.assertEqual(observation.error_number, errno.EPERM)
        self.assertEqual(
            self.evidence.observation("rlimit", "exec").outcome,
            "allowed",
        )

    def test_seatbelt_and_combined_profile_deny_every_escape_path(
        self,
    ) -> None:
        baseline = self.evidence.observation("seatbelt", "baseline")
        self.assertIsNotNone(baseline)
        assert baseline is not None
        if (
            baseline.outcome == "ambiguous"
            and baseline.detail == profile.PROBE_DETAIL_OUTER_SEATBELT_DENIED
        ):
            self.assertFalse(self.evidence.compatible)
            self._skip_or_fail(
                "outer sandbox blocks nested Seatbelt; fail-closed verified"
            )
        self.assertEqual(baseline.outcome, "observed")

        for action in (
            "fork",
            "posix_spawn",
            "popen",
            "double_fork",
            "setsid",
            "setpgid",
            "exec",
        ):
            with self.subTest(layer="seatbelt", action=action):
                observation = self.evidence.observation("seatbelt", action)
                self.assertIsNotNone(observation)
                assert observation is not None
                self.assertEqual(observation.outcome, "denied")
                self.assertEqual(observation.error_number, errno.EPERM)
                self.assertNotEqual(observation.child_pid, os.getpid())

        for action in ("fork", "posix_spawn", "popen", "double_fork"):
            with self.subTest(layer="combined", action=action):
                observation = self.evidence.observation("combined", action)
                self.assertIsNotNone(observation)
                assert observation is not None
                self.assertEqual(observation.outcome, "denied")
                self.assertIn(observation.error_number, {errno.EAGAIN, errno.EPERM})

        for action in ("setsid", "setpgid", "exec"):
            with self.subTest(layer="combined", action=action):
                observation = self.evidence.observation("combined", action)
                self.assertIsNotNone(observation)
                assert observation is not None
                self.assertEqual(observation.outcome, "denied")
                self.assertEqual(observation.error_number, errno.EPERM)

        self.assertTrue(self.evidence.compatible)
        self.assertEqual(
            self.evidence.production_capable,
            self.PRODUCTION_EVIDENCE_EXPECTED,
        )
        self.assertEqual(self.evidence.blockers, ())
        if self.PRODUCTION_EVIDENCE_EXPECTED:
            profile.require_compatible(self.evidence)
        else:
            self.assertNotEqual(self.evidence.runtime_pin, profile.PINNED_RUNTIME)

    def test_secure_owner_snapshot_profile_enforces_exec_and_write_boundaries(
        self,
    ) -> None:
        baseline = self.evidence.observation("seatbelt", "baseline")
        if baseline is None or baseline.outcome != "observed":
            self._skip_or_fail(
                "nested Seatbelt profile is unavailable in this host context"
            )

        with owned_temporary_directory("secure-owner-snapshot-") as temporary:
            root = temporary.resolve(strict=True)
            os.chmod(root, 0o700)
            attestation = _build_owner_snapshot_attestation(
                root,
                source=profile.python_runtime_executable(),
            )
            writable_path = root / "writable"
            outside_root = root / "outside"
            writable_path.mkdir(mode=0o700)
            outside_root.mkdir(mode=0o700)
            outside_path = outside_root / "blocked.json"
            firmlink_snapshot = pathlib.Path("/System/Volumes/Data") / pathlib.Path(
                attestation.snapshot.executable_path
            ).relative_to("/")
            canonical_stat = os.stat(
                attestation.snapshot.executable_path,
                follow_symlinks=False,
            )
            alias_stat = os.stat(firmlink_snapshot, follow_symlinks=False)
            self.assertEqual(
                (canonical_stat.st_dev, canonical_stat.st_ino),
                (alias_stat.st_dev, alias_stat.st_ino),
            )
            writable_fd = os.open(
                writable_path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            writable = profile.attest_writable_root(
                writable_path,
                directory_fd=writable_fd,
            )
            try:
                with mock.patch.object(
                    profile,
                    "probe_compatibility",
                    return_value=self.evidence,
                ):
                    prepared = profile.prepare_custodied_snapshot_no_child_profile(
                        attestation,
                        writable_roots=(writable,),
                    )
                stdin_fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                stdout_read, stdout_write = os.pipe()
                stderr_read, stderr_write = os.pipe()
                launched: profile.LaunchedNoChildProcess | None = None
                reaped = False
                try:
                    launched = profile.launch_prepared_no_child_process(
                        prepared,
                        [
                            attestation.snapshot.executable_path,
                            "-S",
                            "-c",
                            _SECURE_PROFILE_WORKER,
                            str(writable_path),
                            str(outside_path),
                            str(firmlink_snapshot),
                        ],
                        cwd=str(root),
                        environment={
                            "HOME": str(writable_path),
                            "PYTHONDONTWRITEBYTECODE": "1",
                            "PYTHONHOME": sys.base_prefix,
                            "TMPDIR": str(writable_path),
                        },
                        stdin_fd=stdin_fd,
                        stdout_fd=stdout_write,
                        stderr_fd=stderr_write,
                    )
                    os.close(stdout_write)
                    stdout_write = -1
                    os.close(stderr_write)
                    stderr_write = -1
                    stdout = bytearray()
                    while chunk := os.read(stdout_read, 4096):
                        stdout.extend(chunk)
                    stderr = bytearray()
                    while chunk := os.read(stderr_read, 4096):
                        stderr.extend(chunk)
                    _, wait_status = os.waitpid(launched.pid, 0)
                    reaped = True
                    self.assertEqual(os.waitstatus_to_exitcode(wait_status), 0)
                    self.assertEqual(bytes(stderr), b"")
                    self.assertEqual(
                        json.loads(stdout.decode("ascii", "strict")),
                        {
                            "alternate_exec_denied": True,
                            "firmlink_write_denied": True,
                            "network": True,
                            "outside_write_denied": True,
                            "writable_root": True,
                        },
                    )
                    self.assertEqual(
                        (writable_path / "allowed.json").read_text(encoding="ascii"),
                        "allowed\n",
                    )
                    self.assertFalse(outside_path.exists())
                    self.assertEqual(
                        stat.S_IMODE(
                            os.stat(
                                attestation.snapshot.executable_path,
                                follow_symlinks=False,
                            ).st_mode
                        ),
                        0o500,
                    )
                finally:
                    for descriptor in (
                        stdin_fd,
                        stdout_read,
                        stdout_write,
                        stderr_read,
                        stderr_write,
                    ):
                        if descriptor >= 0:
                            try:
                                os.close(descriptor)
                            except OSError:
                                pass
                    if launched is not None and not reaped:
                        try:
                            os.kill(launched.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        try:
                            os.waitpid(launched.pid, 0)
                        except ChildProcessError:
                            pass
            finally:
                os.close(writable_fd)
                _close_owner_snapshot_attestation(attestation)

    def test_public_launcher_returns_bound_leader_evidence(self) -> None:
        executable = pathlib.Path("/bin/sleep").resolve()
        try:
            probe_override = (
                mock.patch.object(
                    profile,
                    "probe_compatibility",
                    return_value=self.evidence,
                )
                if not self.PRODUCTION_EVIDENCE_EXPECTED
                else contextlib.nullcontext()
            )
            with probe_override:
                prepared = profile.prepare_no_child_profile(
                    executable,
                    expected_sha256=_sha256(executable),
                )
        except profile.NoChildProfileUnavailable as error:
            if "seatbelt-baseline-not-observed" in error.evidence.blockers:
                self._skip_or_fail(
                    "outer sandbox blocks nested Seatbelt; fail-closed verified"
                )
            raise

        launched: profile.LaunchedNoChildProcess | None = None
        try:
            launched = profile.launch_prepared_no_child_process(
                prepared,
                [str(executable), "5"],
                cwd="/",
                environment={},
            )
            self.assertEqual(launched.pid, launched.pgid)
            self.assertEqual(launched.pid, launched.session_id)
            self.assertTrue(launched.start_identity)
            self.assertEqual(
                profile.process_start_identity(launched.pid),
                launched.start_identity,
            )
            self.assertEqual(os.getpgid(launched.pid), launched.pid)
            self.assertEqual(os.getsid(launched.pid), launched.pid)
            self.assertEqual(
                launched.profile_sha256,
                hashlib.sha256(prepared.seatbelt_profile.encode("utf-8")).hexdigest(),
            )
            self.assertEqual(
                launched.parent_nproc_before,
                launched.parent_nproc_after,
            )
        finally:
            if launched is not None:
                try:
                    os.kill(launched.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(launched.pid, 0)
                except ChildProcessError:
                    pass


if __name__ == "__main__":
    unittest.main()
