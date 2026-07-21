from __future__ import annotations

import errno
import hashlib
import json
import os
import pathlib
import resource
import signal
import shutil
import stat
import sys
import tempfile
import unittest
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


REQUIRE_LIVE_NO_CHILD_PROFILE_ENV = "CODEX_REVIEW_REQUIRE_LIVE_NO_CHILD_PROFILE"


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
        test_root = pathlib.Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(
            prefix=".owner-snapshot-profile-",
            dir=test_root,
        ) as temporary:
            root = pathlib.Path(temporary).resolve(strict=True)
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
        test_root = pathlib.Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(
            prefix=".owner-snapshot-alias-",
            dir=test_root,
        ) as temporary:
            root = pathlib.Path(temporary).resolve(strict=True)
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
                writable = profile.attest_writable_root(
                    data_alias,
                    directory_fd=alias_fd,
                )
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

    def test_error_pipe_setup_failure_closes_every_created_descriptor(self) -> None:
        error_read, error_write = os.pipe()
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
            profile._open_launch_error_pipe()

        for descriptor in (error_read, error_write):
            with self.subTest(descriptor=descriptor):
                with self.assertRaises(OSError) as raised:
                    os.fstat(descriptor)
                self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_fork_failure_closes_both_error_pipe_descriptors(self) -> None:
        error_read, error_write = os.pipe()
        with (
            mock.patch.object(
                profile,
                "_open_launch_error_pipe",
                return_value=(error_read, error_write),
            ),
            mock.patch.object(
                profile.os,
                "fork",
                side_effect=OSError(errno.EAGAIN, "injected fork failure"),
            ),
            self.assertRaisesRegex(OSError, "injected fork failure"),
        ):
            profile._fork_with_launch_error_pipe()

        for descriptor in (error_read, error_write):
            with self.subTest(descriptor=descriptor):
                with self.assertRaises(OSError) as raised:
                    os.fstat(descriptor)
                self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_dynamic_loader_environment_injection_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "dynamic-loader"):
            profile._validated_environment(
                {"DYLD_INSERT_LIBRARIES": "/synthetic/injected.dylib"}
            )

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
                "_read_executable_identity",
                return_value=sandbox_exec,
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
        test_root = pathlib.Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(
            prefix=".no-child-auth-",
            dir=test_root,
        ) as temporary:
            synthetic = pathlib.Path(temporary) / "synthetic-app-server"
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
        pin = profile.PINNED_RUNTIME
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
        test_root = pathlib.Path(__file__).resolve().parent
        cls._temporary = tempfile.TemporaryDirectory(
            prefix=".no-child-probe-",
            dir=test_root,
        )
        root = pathlib.Path(cls._temporary.name)
        cls.synthetic_python = root / "synthetic-python3.13"
        cls.synthetic_alternate = root / "synthetic-alternate"
        shutil.copyfile(profile.python_runtime_executable(), cls.synthetic_python)
        shutil.copyfile(pathlib.Path("/usr/bin/true"), cls.synthetic_alternate)
        cls.synthetic_python.chmod(0o755)
        cls.synthetic_alternate.chmod(0o755)
        cls.evidence = profile.probe_compatibility(
            probe_executable_path=cls.synthetic_python,
            alternate_executable_path=cls.synthetic_alternate,
            python_home=sys.base_prefix,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()
        super().tearDownClass()

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
        if baseline.outcome == "ambiguous" and "sandbox_apply" in baseline.detail:
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
        self.assertTrue(self.evidence.production_capable)
        self.assertEqual(self.evidence.blockers, ())
        profile.require_compatible(self.evidence)

    def test_secure_owner_snapshot_profile_enforces_exec_and_write_boundaries(
        self,
    ) -> None:
        baseline = self.evidence.observation("seatbelt", "baseline")
        if baseline is None or baseline.outcome != "observed":
            self._skip_or_fail(
                "nested Seatbelt profile is unavailable in this host context"
            )

        test_root = pathlib.Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(
            prefix=".secure-owner-snapshot-",
            dir=test_root,
        ) as temporary:
            root = pathlib.Path(temporary).resolve(strict=True)
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
