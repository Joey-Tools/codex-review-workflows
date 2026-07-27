from __future__ import annotations

import hashlib
import os
import pathlib
import pwd
import stat
import subprocess
import sys
import tempfile
import unittest


SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER = SKILL_ROOT / "scripts" / "install_claude_keychain_broker_macos.sh"
ARTIFACT = SKILL_ROOT / "scripts" / "review_runtime" / "claude_keychain_broker"
EXPECTED_SHA256 = "fcdf6d473ec5c6fa76488da0b115d147fe5e5fa576ed33710ecd3fd7186e0b46"
EXPECTED_SIZE = 101_728


@unittest.skipUnless(sys.platform == "darwin", "requires macOS")
@unittest.skipIf(os.geteuid() == 0, "requires a non-root account")
class ClaudeKeychainBrokerInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.artifact = ARTIFACT.read_bytes()
        if len(cls.artifact) != EXPECTED_SIZE:
            raise AssertionError("broker fixture size does not match the installer pin")
        if hashlib.sha256(cls.artifact).hexdigest() != EXPECTED_SHA256:
            raise AssertionError(
                "broker fixture digest does not match the installer pin"
            )

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(
            prefix="claude-keychain-broker-installer-"
        )
        self.test_root = pathlib.Path(self._temporary.name).resolve()
        self.test_root.chmod(0o700)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _destination(self, root: pathlib.Path | None = None) -> pathlib.Path:
        selected_root = self.test_root if root is None else root
        return (
            selected_root
            / "Library"
            / "Joey-Tools"
            / "CodexReview"
            / "brokers"
            / EXPECTED_SHA256
            / "security"
        )

    def _install_directories(
        self, root: pathlib.Path | None = None
    ) -> list[pathlib.Path]:
        selected_root = self.test_root if root is None else root
        relative = self._destination(selected_root).parent.relative_to(selected_root)
        return [
            selected_root.joinpath(*relative.parts[:index])
            for index in range(1, len(relative.parts) + 1)
        ]

    def _run_installer(
        self,
        payload: bytes,
        *,
        root: pathlib.Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        command = [
            str(INSTALLER),
            "--test-root",
            str(self.test_root if root is None else root),
        ]
        return subprocess.run(
            command,
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
        )

    def _assert_success(self, completed: subprocess.CompletedProcess[bytes]) -> None:
        self.assertEqual(
            completed.returncode,
            0,
            completed.stdout.decode(errors="replace")
            + completed.stderr.decode(errors="replace"),
        )

    def _assert_failure(self, completed: subprocess.CompletedProcess[bytes]) -> None:
        self.assertNotEqual(
            completed.returncode,
            0,
            completed.stdout.decode(errors="replace")
            + completed.stderr.decode(errors="replace"),
        )

    def _acl_listing(self, path: pathlib.Path) -> bytes:
        completed = subprocess.run(
            ["/bin/ls", "-lde", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )
        self.assertEqual(
            completed.returncode, 0, completed.stderr.decode(errors="replace")
        )
        return completed.stdout

    def _assert_no_staging_files(self) -> None:
        digest_directory = self._destination().parent
        if digest_directory.exists():
            self.assertEqual(list(digest_directory.glob(".security.install.*")), [])

    def _render_production_root_program(self) -> bytes:
        rendered = subprocess.run(
            [
                "/bin/bash",
                "-c",
                'source "$1"; build_production_root_program; printf %s "$ROOT_PROGRAM"',
                "installer-test",
                str(INSTALLER),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )
        self._assert_success(rendered)
        return rendered.stdout

    def test_production_root_program_is_frozen_and_syntax_valid(self) -> None:
        root_program = self._render_production_root_program()
        syntax = subprocess.run(
            ["/bin/bash", "-n"],
            input=root_program,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )
        self._assert_success(syntax)
        self.assertIn(b'install_payload "/Library"', root_program)
        self.assertNotIn(os.fsencode(SKILL_ROOT), root_program)
        self.assertNotIn(b"run_test_install", root_program)
        self.assertNotIn(b"require_test_root", root_program)
        self.assertNotIn(b"/usr/bin/sudo", root_program)

    def test_success_installs_final_metadata_and_digest(self) -> None:
        completed = self._run_installer(self.artifact)
        self._assert_success(completed)

        destination = self._destination()
        metadata = os.lstat(destination)
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertFalse(destination.is_symlink())
        self.assertEqual(metadata.st_uid, os.geteuid())
        self.assertEqual(metadata.st_gid, os.getegid())
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o555)
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(metadata.st_size, EXPECTED_SIZE)
        self.assertEqual(
            hashlib.sha256(destination.read_bytes()).hexdigest(), EXPECTED_SHA256
        )
        self.assertEqual(len(self._acl_listing(destination).splitlines()), 1)
        for directory in self._install_directories():
            directory_metadata = os.lstat(directory)
            self.assertTrue(stat.S_ISDIR(directory_metadata.st_mode))
            self.assertFalse(directory.is_symlink())
            self.assertEqual(directory_metadata.st_uid, os.geteuid())
            self.assertEqual(directory_metadata.st_gid, os.getegid())
            self.assertEqual(stat.S_IMODE(directory_metadata.st_mode), 0o755)
            self.assertEqual(len(self._acl_listing(directory).splitlines()), 1)
        signature = subprocess.run(
            [
                "/usr/bin/codesign",
                "--verify",
                "--strict",
                "--all-architectures",
                "--verbose=2",
                str(destination),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        self.assertEqual(
            signature.returncode, 0, signature.stderr.decode(errors="replace")
        )
        self._assert_no_staging_files()

    def test_idempotence_preserves_existing_destination(self) -> None:
        first = self._run_installer(self.artifact)
        self._assert_success(first)
        destination = self._destination()
        before = os.lstat(destination)

        second = self._run_installer(self.artifact)
        self._assert_success(second)
        after = os.lstat(destination)

        self.assertIn(b"already installed", second.stdout)
        self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
        self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(after.st_ctime_ns, before.st_ctime_ns)
        self._assert_no_staging_files()

    def test_concurrent_installers_publish_one_valid_destination(self) -> None:
        command = [str(INSTALLER), "--test-root", str(self.test_root)]
        processes = [
            subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for _attempt in range(2)
        ]
        results = [
            process.communicate(input=self.artifact, timeout=15)
            for process in processes
        ]

        diagnostics = b"\n".join(stdout + stderr for stdout, stderr in results).decode(
            errors="replace"
        )
        self.assertEqual(
            [process.returncode for process in processes], [0, 0], diagnostics
        )
        destination = self._destination()
        metadata = os.lstat(destination)
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o555)
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(
            hashlib.sha256(destination.read_bytes()).hexdigest(),
            EXPECTED_SHA256,
        )
        self._assert_no_staging_files()

    def test_precreated_0755_prefix_supports_install_and_retry(self) -> None:
        directories = self._install_directories()
        directories[-1].mkdir(parents=True, mode=0o755)
        for directory in directories:
            directory.chmod(0o755)
        before = {
            directory: (
                os.lstat(directory),
                self._acl_listing(directory).splitlines()[1:],
            )
            for directory in directories
        }

        first = self._run_installer(self.artifact)
        self._assert_success(first)
        second = self._run_installer(self.artifact)
        self._assert_success(second)

        self.assertIn(b"already installed", second.stdout)
        for directory in directories:
            before_metadata, before_acl = before[directory]
            after_metadata = os.lstat(directory)
            self.assertEqual(
                (
                    after_metadata.st_dev,
                    after_metadata.st_ino,
                    after_metadata.st_uid,
                    after_metadata.st_gid,
                    after_metadata.st_mode,
                ),
                (
                    before_metadata.st_dev,
                    before_metadata.st_ino,
                    before_metadata.st_uid,
                    before_metadata.st_gid,
                    before_metadata.st_mode,
                ),
            )
            self.assertEqual(stat.S_IMODE(after_metadata.st_mode), 0o755)
            self.assertEqual(self._acl_listing(directory).splitlines()[1:], before_acl)
        self._assert_no_staging_files()

    def test_bad_oversized_input_is_rejected(self) -> None:
        completed = self._run_installer(self.artifact + b"\x00")
        self._assert_failure(completed)
        self.assertIn(b"size does not match", completed.stderr)
        self.assertFalse(os.path.lexists(self._destination()))
        self._assert_no_staging_files()

    def test_empty_input_is_rejected(self) -> None:
        completed = self._run_installer(b"")
        self._assert_failure(completed)
        self.assertIn(b"size does not match", completed.stderr)
        self.assertFalse(os.path.lexists(self._destination()))
        self._assert_no_staging_files()

    def test_truncated_input_is_rejected(self) -> None:
        completed = self._run_installer(self.artifact[:-1])
        self._assert_failure(completed)
        self.assertIn(b"size does not match", completed.stderr)
        self.assertFalse(os.path.lexists(self._destination()))
        self._assert_no_staging_files()

    def test_wrong_digest_input_is_rejected(self) -> None:
        wrong_digest = bytearray(self.artifact)
        wrong_digest[0] ^= 0x01
        completed = self._run_installer(bytes(wrong_digest))
        self._assert_failure(completed)
        self.assertIn(b"digest does not match", completed.stderr)
        self.assertFalse(os.path.lexists(self._destination()))
        self._assert_no_staging_files()

    def test_preexisting_directory_metadata_is_not_mutated(self) -> None:
        library = self.test_root / "Library"
        unsafe_directory = library / "Joey-Tools"
        unsafe_directory.mkdir(parents=True)
        library.chmod(0o755)
        unsafe_directory.chmod(0o777)
        before = os.lstat(unsafe_directory)
        before_acl = self._acl_listing(unsafe_directory)

        completed = self._run_installer(self.artifact)
        self._assert_failure(completed)
        after = os.lstat(unsafe_directory)

        self.assertEqual(
            (after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode),
            (
                before.st_dev,
                before.st_ino,
                before.st_uid,
                before.st_gid,
                before.st_mode,
            ),
        )
        self.assertEqual(self._acl_listing(unsafe_directory), before_acl)
        self.assertFalse((unsafe_directory / "CodexReview").exists())

    def test_symlink_ancestor_is_rejected_without_following_it(self) -> None:
        outside = self.test_root / "outside"
        outside.mkdir()
        library = self.test_root / "Library"
        library.symlink_to(outside, target_is_directory=True)

        completed = self._run_installer(self.artifact)
        self._assert_failure(completed)

        self.assertTrue(library.is_symlink())
        self.assertFalse((outside / "Joey-Tools").exists())

    def test_test_root_replacement_is_rejected_before_installation(self) -> None:
        original = self.test_root.with_name(f"{self.test_root.name}-original")
        replacement = self.test_root.with_name(f"{self.test_root.name}-replacement")
        replacement.mkdir(mode=0o700)
        command = r"""
source "$1"
eval "$(declare -f require_test_root | /usr/bin/sed '1s/require_test_root/original_require_test_root/')"
race_once=0
race_target="$2"
race_original="$3"
race_replacement="$4"
require_test_root() {
  original_require_test_root "$@"
  if [[ "$race_once" == 0 ]]; then
    race_once=1
    /bin/mv "$race_target" "$race_original"
    /bin/ln -s "$race_replacement" "$race_target"
  fi
}
run_test_install "$2"
"""
        try:
            completed = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    command,
                    "installer-race-test",
                    str(INSTALLER),
                    str(self.test_root),
                    str(original),
                    str(replacement),
                ],
                input=self.artifact,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=15,
            )
            self._assert_failure(completed)
            self.assertIn(b"identity changed", completed.stderr)
            self.assertFalse((original / "Library").exists())
            self.assertFalse((replacement / "Library").exists())
        finally:
            if self.test_root.is_symlink():
                self.test_root.unlink()
            if original.exists():
                original.rename(self.test_root)
            if replacement.exists():
                replacement.rmdir()

    def test_hardlink_destination_is_rejected_without_mutation(self) -> None:
        installed = self._run_installer(self.artifact)
        self._assert_success(installed)
        destination = self._destination()
        peer = destination.with_name("security-hardlink")
        os.link(destination, peer)
        before = os.lstat(destination)

        completed = self._run_installer(self.artifact)
        self._assert_failure(completed)
        after = os.lstat(destination)

        self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
        self.assertEqual(after.st_nlink, 2)
        self.assertEqual(os.lstat(peer).st_ino, after.st_ino)
        self.assertEqual(stat.S_IMODE(after.st_mode), 0o555)
        self._assert_no_staging_files()

    def test_unsafe_destination_mode_is_rejected_without_repair(self) -> None:
        installed = self._run_installer(self.artifact)
        self._assert_success(installed)
        destination = self._destination()
        destination.chmod(0o755)
        before = os.lstat(destination)

        completed = self._run_installer(self.artifact)
        self._assert_failure(completed)
        after = os.lstat(destination)

        self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
        self.assertEqual(stat.S_IMODE(after.st_mode), 0o755)
        self.assertIn(b"metadata is unsafe", completed.stderr)
        self._assert_no_staging_files()

    def test_destination_acl_is_rejected_without_mutation(self) -> None:
        installed = self._run_installer(self.artifact)
        self._assert_success(installed)
        destination = self._destination()
        username = pwd.getpwuid(os.geteuid()).pw_name
        add_acl = subprocess.run(
            ["/bin/chmod", "+a", f"user:{username} allow read", str(destination)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )
        if add_acl.returncode != 0:
            self.skipTest("filesystem does not support macOS extended ACLs")
        before_acl = self._acl_listing(destination)
        if len(before_acl.splitlines()) == 1:
            self.skipTest("filesystem did not retain a macOS extended ACL")
        before = os.lstat(destination)

        completed = self._run_installer(self.artifact)
        self._assert_failure(completed)
        after = os.lstat(destination)

        self.assertIn(b"extended ACL", completed.stderr)
        self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
        self.assertEqual(self._acl_listing(destination), before_acl)
        self._assert_no_staging_files()

    def test_production_path_is_rejected_as_test_root(self) -> None:
        completed = subprocess.run(
            [str(INSTALLER), "--test-root", "/Library"],
            input=self.artifact,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )
        self._assert_failure(completed)
        self.assertIn(b"must not target a production path", completed.stderr)

    def test_explicit_mode_is_required(self) -> None:
        completed = subprocess.run(
            [str(INSTALLER)],
            input=self.artifact,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )
        self._assert_failure(completed)
        self.assertIn(b"usage:", completed.stderr)


if __name__ == "__main__":
    unittest.main()
