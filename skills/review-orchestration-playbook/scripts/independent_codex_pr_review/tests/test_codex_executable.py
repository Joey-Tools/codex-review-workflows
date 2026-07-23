from __future__ import annotations

import ctypes
import errno
import grp
import hashlib
import json
import os
import pathlib
import pwd
import stat
import subprocess
import sys
import unittest
from collections.abc import Callable
from dataclasses import dataclass, replace
from unittest import mock

import review_supervisor.codex_executable as codex_executable

from review_supervisor.codex_executable import (
    AGGREGATE_SCHEMA_NAME,
    CODESIGN_PATH,
    CommandResult,
    CodexExecutableCustody,
    CodexExecutableCustodyStale,
    CodexExecutableError,
    CodexExecutableExecutionUnsupported,
    CodexExecutablePolicy,
    ExecutableExclusionRoots,
    ExtendedMetadataEvidence,
    NodeIdentity,
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
    verify_macos_filesystem_metadata,
)
from tests.support import owned_temporary_directory


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


class CodexExecutableAuthenticationTests(unittest.TestCase):
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

    def test_strict_directory_metadata_inspection_still_rejects_ctime_churn(
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
            self.assertRaisesRegex(OSError, "changed during inspection"),
        ):
            codex_executable.inspect_macos_filesystem_metadata(
                directory_fd,
                "directory",
            )

    def test_transient_directory_metadata_mutation_changes_the_ctime_window(
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

            with self.assertRaisesRegex(
                CodexExecutableError,
                "metadata raced with inspection",
            ):
                _authenticate(
                    fixture,
                    FakeRunner(fixture),
                    filesystem_metadata_verifier=FakeFilesystemMetadataVerifier(
                        inspect
                    ),
                )
            self.assertTrue(mutated)

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
            os.mkfifo(fifo, 0o700)
            changed = replace(fixture, source=fifo)
            with self.assertRaisesRegex(CodexExecutableError, "not a regular file"):
                _authenticate(changed, FakeRunner(changed))

            link = fixture.source.with_name("codex-hardlink")
            os.link(fixture.source, link)
            with self.assertRaisesRegex(CodexExecutableError, "hard-link count"):
                _authenticate(fixture, FakeRunner(fixture))

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


class CodexExecutableCustodyTests(unittest.TestCase):
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
                    with self.assertRaisesRegex(
                        CodexExecutableCustodyStale,
                        "suspicious paths were retained",
                    ):
                        custody.cleanup()
                    self.assertTrue(custody.closed)
                    self.assertTrue(custody.retained_snapshot)

    def test_disappearance_hardlink_and_parent_mode_change_are_rejected(self) -> None:
        mutations = ("disappear", "hardlink", "parent-mode")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with owned_temporary_directory(f"codex-{mutation}-") as root:
                    fixture = _build_fixture(root)
                    custody = _authenticate(fixture, FakeRunner(fixture))
                    snapshot_path = custody.snapshot_path
                    if mutation == "disappear":
                        snapshot_path.unlink()
                    elif mutation == "hardlink":
                        os.link(snapshot_path, snapshot_path.with_name("codex-link"))
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
                        with self.assertRaises(CodexExecutableCustodyStale):
                            custody.cleanup()

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
