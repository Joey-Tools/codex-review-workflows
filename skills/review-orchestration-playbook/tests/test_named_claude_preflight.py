from __future__ import annotations

import json
import hashlib
import errno
import os
import pathlib
import shlex
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock


SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
PREFLIGHT = SCRIPTS / "named_claude_preflight"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import (  # noqa: E402
    claude_capabilities,
    claude_linux,
    claude_provenance,
    claude_version_policy,
)
from review_runtime import named_claude_preflight as preflight_module  # noqa: E402


class NamedClaudePreflightTest(unittest.TestCase):
    @staticmethod
    def _supported_help() -> bytes:
        lines = ["Usage: claude [options]", "", "Options:"]
        for option in claude_capabilities.CLAUDE_REQUIRED_OPTIONS:
            if option == "--safe-mode":
                description = (
                    "Start with all customizations (CLAUDE.md, skills, plugins, "
                    "hooks, MCP servers, custom commands and agents, output styles, "
                    "workflows, custom themes, keybindings, and more) disabled. "
                    "Admin-managed (policy) settings still apply. Auth, model "
                    "selection, built-in tools, and permissions work normally. "
                    "Sets CLAUDE_CODE_SAFE_MODE=1."
                )
            elif option == "--permission-mode":
                description = "Permission mode (choices: default, dontAsk, plan)."
            else:
                description = "Supported option."
            lines.append(f"  {option} <value>  {description}")
        return ("\n".join(lines) + "\n").encode()

    def _write_candidate(
        self,
        path: pathlib.Path,
        *,
        marker: pathlib.Path | None = None,
        version: str = "2.1.212",
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = ["#!/bin/sh"]
        if marker is not None:
            lines.append(f"printf '%s\\n' executed >> {shlex.quote(str(marker))}")
        lines.append('if [ "${1-}" = "--help" ]; then')
        for line in self._supported_help().decode("utf-8").splitlines():
            lines.append(f"  printf '%s\\n' {shlex.quote(line)}")
        lines.extend(
            (
                "  exit 0",
                "fi",
                f"printf '%s\\n' {shlex.quote(f'{version} (Claude Code)')}",
                "exit 0",
            )
        )
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        path.chmod(0o755)

    def _run(
        self,
        *,
        home: pathlib.Path,
        path: str,
        args: tuple[str, ...] = (),
        cwd: pathlib.Path | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "HOME": str(home),
            "PATH": path,
            "LANG": "C",
            "LC_ALL": "C",
        }
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            (sys.executable, str(PREFLIGHT), *args),
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=15,
        )

    def _verified(
        self,
        path: pathlib.Path,
        probe_result: preflight_module.ProbeResult | None = None,
        *,
        release_version: str = "2.1.212",
        help_probe_result: preflight_module.ProbeResult | None = None,
    ) -> preflight_module.VerifiedCandidate:
        resolved = path.resolve(strict=True)
        manifest_url, signature_url = claude_provenance.release_artifact_urls(
            release_version
        )
        return preflight_module.VerifiedCandidate(
            artifact=claude_provenance.ClaudeReleaseArtifact(
                version=release_version,
                platform_key="darwin-arm64",
                binary="claude",
                checksum=hashlib.sha256(resolved.read_bytes()).hexdigest(),
                size=resolved.stat().st_size,
            ),
            resolved_path=resolved,
            identity=preflight_module._identity(resolved),
            manifest_url=manifest_url,
            signature_url=signature_url,
            version_probe_result=probe_result
            or preflight_module.ProbeResult(
                0,
                f"{release_version} (Claude Code)\n".encode(),
                b"",
            ),
            help_probe_result=help_probe_result
            or preflight_module.ProbeResult(0, self._supported_help(), b""),
        )

    def _verified_with_probe(
        self,
        path: pathlib.Path,
        release_version: str,
        version_probe: preflight_module.VersionProbe,
        help_probe: preflight_module.HelpProbe,
    ) -> preflight_module.VerifiedCandidate:
        return self._verified(
            path,
            version_probe(path),
            release_version=release_version,
            help_probe_result=help_probe(path),
        )

    def test_only_active_2_1_216_is_accepted_without_direct_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            marker = root / "active-invocations"
            installed = home / ".local/share/claude/versions/2.1.216"
            self._write_candidate(installed, marker=marker, version="2.1.216")
            active = home / ".local/bin/claude"
            active.parent.mkdir(parents=True)
            active.symlink_to(installed)

            def verifier(
                path: pathlib.Path,
                release_version: str,
                _version_probe: preflight_module.VersionProbe,
                _help_probe: preflight_module.HelpProbe,
            ) -> preflight_module.VerifiedCandidate:
                return self._verified(path, release_version=release_version)

            value = preflight_module.preflight(home=home, verifier=verifier)

            self.assertEqual(value["classification"], "accepted")
            self.assertEqual(value["reason"], "compatible-version-selected")
            self.assertEqual(value["declared_version"], "2.1.216")
            self.assertEqual(value["observed_version"], "2.1.216")
            self.assertEqual(value["selected_version"], "2.1.216")
            self.assertEqual(value["source"], "side-by-side-compatible")
            self.assertFalse(marker.exists())

    def test_compatible_stable_release_matrix_is_not_rejected_by_version(self) -> None:
        for version in ("2.1.211", "2.1.216", "2.99.999"):
            with (
                self.subTest(version=version),
                tempfile.TemporaryDirectory() as temporary,
            ):
                home = pathlib.Path(temporary) / "home"
                installed = home / ".local/share/claude/versions" / version
                self._write_candidate(installed, version=version)

                value = preflight_module.preflight(
                    home=home,
                    verifier=self._verified_with_probe,
                )

                self.assertEqual(value["classification"], "accepted")
                self.assertEqual(value["selected_version"], version)
                self.assertEqual(
                    value["compatible_version_range"],
                    claude_version_policy.CLAUDE_COMPATIBILITY_SPEC,
                )

    def test_explicit_arbitrary_path_accepts_a_separate_compatible_version(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate = pathlib.Path(temporary) / "versions/claude"
            self._write_candidate(candidate, version="2.1.216")

            value = preflight_module.preflight(
                explicit_path=candidate,
                explicit_version="2.1.216",
                verifier=self._verified_with_probe,
            )

            self.assertEqual(value["classification"], "accepted")
            self.assertEqual(value["source"], "explicit-override")
            self.assertEqual(value["selected_version"], "2.1.216")

    def test_controlled_active_install_accepts_compatible_resolved_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            installed = root / "external/versions/2.1.216"
            self._write_candidate(installed, version="2.1.216")
            active = home / ".local/bin/claude"
            active.parent.mkdir(parents=True)
            active.symlink_to(installed)

            value = preflight_module.preflight(
                home=home,
                verifier=self._verified_with_probe,
            )

            self.assertEqual(value["classification"], "accepted")
            self.assertEqual(value["source"], "active-installed")
            self.assertEqual(value["selected_version"], "2.1.216")

    def test_symlinked_home_allows_legitimately_absent_side_by_side_fallback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            real_home = root / "real-home"
            installed = root / "external/versions/2.1.216"
            self._write_candidate(installed, version="2.1.216")
            active = real_home / ".local/bin/claude"
            active.parent.mkdir(parents=True)
            active.symlink_to(installed)
            home = root / "home"
            home.symlink_to(real_home, target_is_directory=True)

            value = preflight_module.preflight(
                home=home,
                verifier=self._verified_with_probe,
            )

            self.assertEqual(value["classification"], "accepted")
            self.assertEqual(value["source"], "active-installed")
            self.assertEqual(value["selected_version"], "2.1.216")

    def test_home_retarget_during_active_fallback_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            first_home = root / "first-home"
            first_home.mkdir()
            second_home = root / "second-home"
            installed = second_home / ".local/share/claude/versions/2.1.216"
            self._write_candidate(installed, version="2.1.216")
            active = second_home / ".local/bin/claude"
            active.parent.mkdir(parents=True)
            active.symlink_to(installed)
            home = root / "home"
            home.symlink_to(first_home, target_is_directory=True)
            original_active_candidate = preflight_module._active_home_candidate

            def retarget_before_active_fallback(**kwargs):  # type: ignore[no-untyped-def]
                home.unlink()
                home.symlink_to(second_home, target_is_directory=True)
                return original_active_candidate(**kwargs)

            verifier = mock.Mock(
                side_effect=AssertionError(
                    "a retargeted HOME must stop before candidate verification"
                )
            )
            with mock.patch.object(
                preflight_module,
                "_active_home_candidate",
                side_effect=retarget_before_active_fallback,
            ):
                value = preflight_module.preflight(home=home, verifier=verifier)

            verifier.assert_not_called()
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    def test_dangling_home_stops_before_trusted_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve(strict=True)
            home = root / "home"
            home.symlink_to(root / "missing-home", target_is_directory=True)
            trusted = root / "trusted-claude"
            self._write_candidate(trusted)
            verifier = mock.Mock(
                side_effect=AssertionError(
                    "a dangling HOME must stop before trusted fallback"
                )
            )

            with mock.patch.object(
                preflight_module,
                "TRUSTED_ACTIVE_PATHS",
                (trusted,),
            ):
                value = preflight_module.preflight(home=home, verifier=verifier)

            verifier.assert_not_called()
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    def test_existing_relative_home_stops_before_trusted_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve(strict=True)
            real_home = root / "home"
            real_home.mkdir()
            relative_home = pathlib.Path(os.path.relpath(real_home, pathlib.Path.cwd()))
            trusted = root / "trusted-claude"
            self._write_candidate(trusted)
            verifier = mock.Mock(
                side_effect=AssertionError(
                    "a relative HOME must stop before trusted fallback"
                )
            )

            with mock.patch.object(
                preflight_module,
                "TRUSTED_ACTIVE_PATHS",
                (trusted,),
            ):
                value = preflight_module.preflight(
                    home=relative_home,
                    verifier=verifier,
                )

            verifier.assert_not_called()
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    def test_dangling_home_ancestor_stops_before_trusted_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve(strict=True)
            dangling_parent = root / "dangling-parent"
            dangling_parent.symlink_to(
                root / "missing-parent",
                target_is_directory=True,
            )
            home = dangling_parent / "home"
            trusted = root / "trusted-claude"
            self._write_candidate(trusted)
            verifier = mock.Mock(
                side_effect=AssertionError(
                    "a dangling HOME ancestor must stop before trusted fallback"
                )
            )

            with mock.patch.object(
                preflight_module,
                "TRUSTED_ACTIVE_PATHS",
                (trusted,),
            ):
                value = preflight_module.preflight(home=home, verifier=verifier)

            verifier.assert_not_called()
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    def test_exact_missing_home_and_trusted_path_allow_ordered_fallback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve(strict=True)
            home = root / "missing-home"
            missing_trusted = root / "missing-trusted/bin/claude"
            missing_trusted.parent.mkdir(parents=True)
            installed = root / "versions/2.1.216"
            self._write_candidate(installed, version="2.1.216")
            trusted = root / "trusted/bin/claude"
            trusted.parent.mkdir(parents=True)
            trusted.symlink_to(installed)

            with mock.patch.object(
                preflight_module,
                "TRUSTED_ACTIVE_PATHS",
                (missing_trusted, trusted),
            ):
                value = preflight_module.preflight(
                    home=home,
                    verifier=self._verified_with_probe,
                )

            self.assertEqual(value["classification"], "accepted")
            self.assertEqual(value["source"], "active-installed")
            self.assertEqual(value["selected_version"], "2.1.216")

    def test_dangling_trusted_ancestor_stops_lower_priority_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve(strict=True)
            home = root / "missing-home"
            dangling_root = root / "dangling-root"
            dangling_root.symlink_to(
                root / "missing-root",
                target_is_directory=True,
            )
            higher = dangling_root / "bin/claude"
            lower = root / "lower/bin/claude"
            self._write_candidate(lower)
            verifier = mock.Mock(
                side_effect=AssertionError(
                    "a dangling trusted ancestor must stop ordered fallback"
                )
            )

            with mock.patch.object(
                preflight_module,
                "TRUSTED_ACTIVE_PATHS",
                (higher, lower),
            ):
                value = preflight_module.preflight(home=home, verifier=verifier)

            verifier.assert_not_called()
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    def test_trusted_candidate_replacement_after_selection_is_inconclusive(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve(strict=True)
            home = root / "missing-home"
            installed = root / "versions/2.1.216"
            self._write_candidate(installed, version="2.1.216")
            trusted = root / "trusted/bin/claude"
            trusted.parent.mkdir(parents=True)
            trusted.symlink_to(installed)
            original_exists = preflight_module._candidate_exists
            replaced = False

            def replace_after_selection(path: pathlib.Path) -> bool:
                nonlocal replaced
                if path == trusted and not replaced:
                    replaced = True
                    replacement = trusted.with_name("claude.replacement")
                    replacement.symlink_to(installed)
                    os.replace(replacement, trusted)
                    return True
                return original_exists(path)

            verifier = mock.Mock(
                side_effect=AssertionError(
                    "a replaced trusted candidate must not be verified"
                )
            )
            with (
                mock.patch.object(
                    preflight_module,
                    "TRUSTED_ACTIVE_PATHS",
                    (trusted,),
                ),
                mock.patch.object(
                    preflight_module,
                    "_candidate_exists",
                    side_effect=replace_after_selection,
                ),
            ):
                value = preflight_module.preflight(home=home, verifier=verifier)

            verifier.assert_not_called()
            self.assertTrue(replaced)
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    def test_out_of_range_and_prerelease_versions_stop_before_verification(
        self,
    ) -> None:
        for version in ("2.1.210", "2.1.211-beta.1", "3.0.0"):
            with (
                self.subTest(version=version),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = pathlib.Path(temporary)
                candidate = root / "claude"
                marker = root / "invocations"
                self._write_candidate(candidate, marker=marker, version=version)
                verifier_called = False

                def forbidden_verifier(
                    _path: pathlib.Path,
                    _release_version: str,
                    _version_probe: preflight_module.VersionProbe,
                    _help_probe: preflight_module.HelpProbe,
                ) -> preflight_module.VerifiedCandidate:
                    nonlocal verifier_called
                    verifier_called = True
                    raise AssertionError("unsupported version must not be verified")

                value = preflight_module.preflight(
                    explicit_path=candidate,
                    explicit_version=version,
                    verifier=forbidden_verifier,
                )

                self.assertFalse(verifier_called)
                self.assertFalse(marker.exists())
                self.assertEqual(value["classification"], "blocked")
                self.assertEqual(value["reason"], "unsupported-version")

    def test_highest_compatible_side_by_side_release_is_selected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary) / "home"
            versions = home / ".local/share/claude/versions"
            for version in ("2.1.211", "2.1.216", "2.99.1", "3.0.0"):
                self._write_candidate(versions / version, version=version)

            value = preflight_module.preflight(
                home=home,
                verifier=self._verified_with_probe,
            )

            self.assertEqual(value["classification"], "accepted")
            self.assertEqual(value["selected_version"], "2.99.1")
            self.assertEqual(
                value["resolved_path"],
                str((versions / "2.99.1").resolve()),
            )

    def test_signed_and_observed_release_versions_must_match_exactly(self) -> None:
        for observed_version in ("2.1.217", "3.0.0"):
            with (
                self.subTest(observed_version=observed_version),
                tempfile.TemporaryDirectory() as temporary,
            ):
                home = pathlib.Path(temporary) / "home"
                installed = home / ".local/share/claude/versions/2.1.216"
                self._write_candidate(installed, version="2.1.216")

                def mismatched_verifier(
                    path: pathlib.Path,
                    release_version: str,
                    _version_probe: preflight_module.VersionProbe,
                    _help_probe: preflight_module.HelpProbe,
                ) -> preflight_module.VerifiedCandidate:
                    return self._verified(
                        path,
                        preflight_module.ProbeResult(
                            0,
                            f"{observed_version} (Claude Code)\n".encode(),
                            b"",
                        ),
                        release_version=release_version,
                    )

                value = preflight_module.preflight(
                    home=home,
                    verifier=mismatched_verifier,
                )

                self.assertEqual(value["classification"], "blocked")
                self.assertEqual(value["reason"], "signed-version-identity-mismatch")
                self.assertEqual(value["declared_version"], "2.1.216")
                self.assertEqual(value["observed_version"], observed_version)

    def test_capability_and_stream_contract_fail_closed_after_version_acceptance(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary) / "home"
            installed = home / ".local/share/claude/versions/2.1.216"
            self._write_candidate(installed, version="2.1.216")

            def missing_capability(
                path: pathlib.Path,
                release_version: str,
                _version_probe: preflight_module.VersionProbe,
                _help_probe: preflight_module.HelpProbe,
            ) -> preflight_module.VerifiedCandidate:
                return self._verified(
                    path,
                    release_version=release_version,
                    help_probe_result=preflight_module.ProbeResult(
                        0,
                        b"Usage: claude\n",
                        b"",
                    ),
                )

            self.assertEqual(
                preflight_module.preflight(
                    home=home,
                    verifier=missing_capability,
                )["reason"],
                "capability-contract-mismatch",
            )

            with mock.patch.object(
                preflight_module,
                "load_stream_contract",
                side_effect=preflight_module.ClaudeStreamContractError(
                    "synthetic contract drift"
                ),
            ):
                value = preflight_module.preflight(
                    home=home,
                    verifier=self._verified_with_probe,
                )

            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "stream-contract-inconclusive")

    def test_declared_version_mismatch_loses_to_descriptor_identity_drift(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            marker = root / "active-invocations"
            installed = home / ".local/share/claude/versions/3.0.0"
            self._write_candidate(installed, marker=marker, version="3.0.0")
            active = home / ".local/bin/claude"
            active.parent.mkdir(parents=True)
            active.symlink_to(installed)
            original_stable_identity = preflight_module._stable_descriptor_identity
            calls = 0

            def rewrite_after_binding(path: pathlib.Path) -> dict[str, int]:
                nonlocal calls
                calls += 1
                identity = original_stable_identity(path)
                if calls == 1:
                    before = path.stat(follow_symlinks=False)
                    payload = path.read_bytes()
                    replacement = path.with_name(f"{path.name}.replacement")
                    replacement.write_bytes(payload)
                    replacement.chmod(before.st_mode & 0o7777)
                    os.utime(
                        replacement,
                        ns=(before.st_atime_ns, before.st_mtime_ns),
                        follow_symlinks=False,
                    )
                    replacement_identity = preflight_module._identity(replacement)
                    self.assertNotEqual(
                        replacement_identity["inode"],
                        identity["inode"],
                    )
                    os.replace(replacement, path)
                    after = preflight_module._identity(path)
                    self.assertEqual(after["size"], identity["size"])
                    self.assertEqual(after["mtime_ns"], identity["mtime_ns"])
                    self.assertNotEqual(after["inode"], identity["inode"])
                return identity

            with mock.patch.object(
                preflight_module,
                "_stable_descriptor_identity",
                side_effect=rewrite_after_binding,
            ):
                value = preflight_module.preflight(home=home)

            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "executable-identity-drift")
            self.assertEqual(value["declared_version"], "3.0.0")
            self.assertFalse(marker.exists())

    def test_side_by_side_compatible_is_verified_before_capability_probes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            exact = home / ".local/share/claude/versions/2.1.212"
            self._write_candidate(exact)
            calls: list[tuple[str, pathlib.Path]] = []

            def verifier(
                path: pathlib.Path,
                release_version: str,
                version_probe: preflight_module.VersionProbe,
                help_probe: preflight_module.HelpProbe,
            ) -> preflight_module.VerifiedCandidate:
                calls.append(("verify", path))
                return self._verified(
                    path,
                    version_probe(path),
                    release_version=release_version,
                    help_probe_result=help_probe(path),
                )

            def version_probe(path: pathlib.Path) -> preflight_module.ProbeResult:
                calls.append(("version", path))
                return preflight_module.ProbeResult(
                    0,
                    b"2.1.212 (Claude Code)\n",
                    b"",
                )

            def help_probe(path: pathlib.Path) -> preflight_module.ProbeResult:
                calls.append(("help", path))
                return preflight_module.ProbeResult(0, self._supported_help(), b"")

            value = preflight_module.preflight(
                home=home,
                verifier=verifier,
                version_probe=version_probe,
                help_probe=help_probe,
            )

            self.assertEqual(value["classification"], "accepted")
            self.assertEqual(value["source"], "side-by-side-compatible")
            self.assertEqual(value["resolved_path"], str(exact.resolve()))
            self.assertEqual(
                [name for name, _path in calls],
                ["verify", "version", "help"],
            )
            self.assertEqual(calls[0][1], exact.resolve())
            self.assertEqual(calls[1][1], exact.resolve())
            self.assertEqual(calls[2][1], exact.resolve())

    def test_wrong_explicit_override_does_not_fall_back_or_execute(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            explicit_marker = root / "explicit-invocations"
            side_marker = root / "side-invocations"
            explicit = root / "versions/3.0.0"
            exact = home / ".local/share/claude/versions/2.1.212"
            self._write_candidate(
                explicit,
                marker=explicit_marker,
                version="3.0.0",
            )
            self._write_candidate(exact, marker=side_marker)

            completed = self._run(
                home=home,
                path="",
                args=("--claude-path", str(explicit)),
            )
            value = json.loads(completed.stdout)

            self.assertEqual(completed.returncode, 1)
            self.assertEqual(value["reason"], "unsupported-version")
            self.assertEqual(value["source"], "explicit-override")
            self.assertFalse(explicit_marker.exists())
            self.assertFalse(side_marker.exists())

    def test_present_exact_path_that_is_a_script_is_never_executed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            marker = root / "script-invocations"
            exact = home / ".local/share/claude/versions/2.1.212"
            self._write_candidate(exact, marker=marker)

            completed = self._run(home=home, path="")
            value = json.loads(completed.stdout)

            self.assertEqual(completed.returncode, 1)
            self.assertEqual(value["classification"], "blocked")
            self.assertEqual(value["reason"], "compatible-version-unavailable")
            self.assertFalse(marker.exists())

    def test_untrusted_path_candidate_is_ignored_and_never_executed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            marker = root / "path-invocations"
            injected = root / "repo/bin/claude"
            self._write_candidate(injected, marker=marker)

            with (
                mock.patch.dict(os.environ, {"PATH": str(injected.parent)}),
                mock.patch.object(preflight_module, "TRUSTED_ACTIVE_PATHS", ()),
            ):
                value = preflight_module.preflight(home=home)

            self.assertEqual(value["reason"], "compatible-version-unavailable")
            self.assertFalse(marker.exists())

    def test_candidate_presence_io_failure_stops_before_lower_priority_fallback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            versions_root = home / ".local/share/claude/versions"
            versions_root.mkdir(parents=True)
            active = home / ".local/bin/claude"
            self._write_candidate(active)
            verifier_called = False

            def forbidden_verifier(
                _path: pathlib.Path,
                _release_version: str,
                _version_probe: preflight_module.VersionProbe,
                _help_probe: preflight_module.HelpProbe,
            ) -> preflight_module.VerifiedCandidate:
                nonlocal verifier_called
                verifier_called = True
                raise AssertionError("lower-priority candidate must not be verified")

            with mock.patch.object(
                preflight_module.os,
                "scandir",
                side_effect=OSError(
                    errno.EIO, "synthetic candidate inspection failure"
                ),
            ):
                value = preflight_module.preflight(
                    home=home,
                    verifier=forbidden_verifier,
                )

            self.assertFalse(verifier_called)
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    def test_malformed_side_by_side_root_stops_before_active_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            versions_root = home / ".local/share/claude/versions"
            versions_root.parent.mkdir(parents=True)
            versions_root.write_text("not a directory", encoding="utf-8")
            active = home / ".local/bin/claude"
            self._write_candidate(active)
            verifier = mock.Mock(
                side_effect=AssertionError(
                    "a malformed higher-priority root must stop selection"
                )
            )

            value = preflight_module.preflight(home=home, verifier=verifier)

            verifier.assert_not_called()
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    def test_malformed_active_ancestor_stops_before_trusted_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            malformed_active_ancestor = home / ".local/bin"
            malformed_active_ancestor.parent.mkdir(parents=True)
            malformed_active_ancestor.write_text(
                "not a directory",
                encoding="utf-8",
            )
            trusted = root / "trusted-claude"
            self._write_candidate(trusted)
            verifier = mock.Mock(
                side_effect=AssertionError(
                    "a malformed higher-priority active path must stop selection"
                )
            )

            with mock.patch.object(
                preflight_module,
                "TRUSTED_ACTIVE_PATHS",
                (trusted,),
            ):
                value = preflight_module.preflight(home=home, verifier=verifier)

            verifier.assert_not_called()
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    def test_dangling_active_ancestor_stops_before_trusted_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            dangling_active_ancestor = home / ".local/bin"
            dangling_active_ancestor.parent.mkdir(parents=True)
            dangling_active_ancestor.symlink_to(
                root / "missing-bin",
                target_is_directory=True,
            )
            trusted = root / "trusted-claude"
            self._write_candidate(trusted)
            verifier = mock.Mock(
                side_effect=AssertionError(
                    "a dangling higher-priority active path must stop selection"
                )
            )

            with mock.patch.object(
                preflight_module,
                "TRUSTED_ACTIVE_PATHS",
                (trusted,),
            ):
                value = preflight_module.preflight(home=home, verifier=verifier)

            verifier.assert_not_called()
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    def test_malformed_side_by_side_ancestor_stops_before_trusted_fallback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            malformed_ancestor = home / ".local/share"
            malformed_ancestor.parent.mkdir(parents=True)
            malformed_ancestor.write_text("not a directory", encoding="utf-8")
            trusted = root / "trusted-claude"
            self._write_candidate(trusted)
            verifier = mock.Mock(
                side_effect=AssertionError(
                    "a malformed higher-priority ancestor must stop selection"
                )
            )

            with mock.patch.object(
                preflight_module,
                "TRUSTED_ACTIVE_PATHS",
                (trusted,),
            ):
                value = preflight_module.preflight(home=home, verifier=verifier)

            verifier.assert_not_called()
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    def test_dangling_side_by_side_ancestor_stops_before_active_fallback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            dangling_ancestor = home / ".local/share"
            dangling_ancestor.parent.mkdir(parents=True)
            dangling_ancestor.symlink_to(
                root / "missing-share",
                target_is_directory=True,
            )
            active = home / ".local/bin/claude"
            self._write_candidate(active)
            verifier = mock.Mock(
                side_effect=AssertionError(
                    "a dangling higher-priority ancestor must stop selection"
                )
            )

            value = preflight_module.preflight(home=home, verifier=verifier)

            verifier.assert_not_called()
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    def test_observed_side_by_side_root_disappearance_stops_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            versions_root = home / ".local/share/claude/versions"
            versions_root.mkdir(parents=True)
            active = home / ".local/bin/claude"
            self._write_candidate(active)
            verifier = mock.Mock(
                side_effect=AssertionError(
                    "an observed higher-priority root race must stop selection"
                )
            )

            real_open = preflight_module.os.open

            def disappear_before_root_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
                if path == "versions":
                    raise FileNotFoundError(
                        errno.ENOENT,
                        "synthetic side-by-side root disappearance",
                    )
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(
                preflight_module.os,
                "open",
                side_effect=disappear_before_root_open,
            ):
                value = preflight_module.preflight(home=home, verifier=verifier)

            verifier.assert_not_called()
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    def test_side_by_side_path_appearance_during_absence_stops_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            parent = home / ".local/share/claude"
            parent.mkdir(parents=True)
            (parent / "versions").mkdir()
            active = home / ".local/bin/claude"
            self._write_candidate(active)
            verifier = mock.Mock(
                side_effect=AssertionError(
                    "an unstable higher-priority absence must stop selection"
                )
            )
            real_stat = preflight_module.os.stat
            observed_missing = False

            def appear_during_recheck(path, *args, **kwargs):  # type: ignore[no-untyped-def]
                nonlocal observed_missing
                if path == "versions" and not observed_missing:
                    observed_missing = True
                    raise FileNotFoundError(
                        errno.ENOENT,
                        "synthetic initially absent side-by-side root",
                    )
                return real_stat(path, *args, **kwargs)

            with mock.patch.object(
                preflight_module.os,
                "stat",
                side_effect=appear_during_recheck,
            ):
                value = preflight_module.preflight(home=home, verifier=verifier)

            verifier.assert_not_called()
            self.assertTrue(observed_missing)
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    def test_observed_automatic_candidate_disappearance_is_inconclusive(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            side_by_side = home / ".local/share/claude/versions/2.1.212"
            active = home / ".local/bin/claude"
            self._write_candidate(side_by_side)
            self._write_candidate(active)
            canonical_side_by_side = side_by_side.resolve(strict=True)
            original_exists = preflight_module._candidate_exists
            observed = False

            def observe_then_remove(path: pathlib.Path) -> bool:
                nonlocal observed
                if path == canonical_side_by_side and not observed:
                    observed = True
                    side_by_side.unlink()
                    return True
                return original_exists(path)

            with mock.patch.object(
                preflight_module,
                "_candidate_exists",
                side_effect=observe_then_remove,
            ):
                value = preflight_module.preflight(
                    home=home,
                    verifier=mock.Mock(
                        side_effect=AssertionError(
                            "a raced automatic candidate must stop selection"
                        )
                    ),
                )

            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")
            self.assertEqual(value["source"], "side-by-side-compatible")

    def test_explicit_candidate_resolve_io_failure_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            candidate = root / "claude"
            self._write_candidate(candidate)
            original_resolve = pathlib.Path.resolve

            def fail_candidate_resolve(
                path: pathlib.Path,
                *args: object,
                **kwargs: object,
            ) -> pathlib.Path:
                if path == candidate:
                    raise OSError(errno.ESTALE, "synthetic stale candidate path")
                return original_resolve(path, *args, **kwargs)  # type: ignore[arg-type]

            with mock.patch.object(
                pathlib.Path,
                "resolve",
                autospec=True,
                side_effect=fail_candidate_resolve,
            ):
                value = preflight_module.preflight(explicit_path=candidate)

            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    def test_missing_compatible_version_is_stable_blocked_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            empty_path = root / "empty-bin"
            empty_path.mkdir()
            missing = root / "missing-claude"

            arguments = ("--claude-path", str(missing))
            first = self._run(home=home, path=str(empty_path), args=arguments)
            second = self._run(home=home, path=str(empty_path), args=arguments)

            self.assertEqual(first.returncode, 1)
            self.assertEqual(first.stdout, second.stdout)
            self.assertEqual(first.stderr, second.stderr, "")
            self.assertEqual(first.stdout.count("\n"), 1)
            self.assertLessEqual(len(first.stdout.encode("utf-8")), 16 * 1024)
            self.assertEqual(
                json.loads(first.stdout),
                {
                    "classification": "blocked",
                    "compatible_version_range": ">=2.1.211,<3.0.0",
                    "reason": "compatible-version-unavailable",
                    "source": "explicit-override",
                },
            )

    def test_probe_uses_fixed_credential_free_environment_and_no_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            repo = root / "repo-with-private-context"
            repo.mkdir()
            exact = home / ".local/share/claude/versions/2.1.212"
            self._write_candidate(exact)
            observed: list[tuple[object, dict[str, object]]] = []

            def bounded_capture(*args, **kwargs):  # type: ignore[no-untyped-def]
                observed.append((args, kwargs))
                argument = args[0][1]
                return types.SimpleNamespace(
                    returncode=0,
                    stdout=bytearray(
                        self._supported_help()
                        if argument == "--help"
                        else b"2.1.212 (Claude Code)\n"
                    ),
                    stderr=bytearray(),
                )

            with mock.patch.object(
                preflight_module,
                "run_bounded_capture",
                side_effect=bounded_capture,
            ):
                value = preflight_module.preflight(
                    home=home,
                    verifier=self._verified_with_probe,
                    version_probe=preflight_module.probe_verified_version,
                )

            self.assertEqual(value["classification"], "accepted")
            self.assertEqual(
                [args for args, _kwargs in observed],
                [
                    ((str(exact.resolve()), "--version"),),
                    ((str(exact.resolve()), "--help"),),
                ],
            )
            for _args, kwargs in observed:
                self.assertEqual(kwargs["cwd"], pathlib.Path("/"))
                self.assertEqual(
                    kwargs["env"],
                    dict(preflight_module.CAPABILITY_PROBE_ENV),
                )
                self.assertIsNone(kwargs["stdin"])
            self.assertNotIn(str(repo), repr(observed))
            environment = observed[0][1]["env"]
            self.assertNotIn("ANTHROPIC_API_KEY", environment)
            self.assertNotIn("CLAUDE_CODE_OAUTH_TOKEN", environment)
            self.assertNotIn("GITHUB_TOKEN", environment)

    def test_default_verifier_probes_private_snapshot_not_candidate_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            installed = home / ".local/share/claude/versions/2.1.216"
            self._write_candidate(installed, version="2.1.216")
            payload = installed.read_bytes()
            observed_probe_paths: list[tuple[str, pathlib.Path]] = []

            def release_verifier(
                executable: pathlib.Path,
                *,
                version: str,
                platform_key: str,
                gpg_temp_root: pathlib.Path,
            ) -> claude_provenance.VerifiedClaudeExecutable:
                del gpg_temp_root
                resolved = executable.resolve(strict=True)
                manifest_url, signature_url = claude_provenance.release_artifact_urls(
                    version
                )
                return claude_provenance.VerifiedClaudeExecutable(
                    executable=resolved,
                    artifact=claude_provenance.ClaudeReleaseArtifact(
                        version=version,
                        platform_key=platform_key,
                        binary="claude",
                        checksum=hashlib.sha256(payload).hexdigest(),
                        size=len(payload),
                    ),
                    manifest_url=manifest_url,
                    signature_url=signature_url,
                    gpg_path=pathlib.Path("/trusted/gpg"),
                    source_identity=claude_provenance._stat_identity(
                        resolved.stat(follow_symlinks=False)
                    ),
                )

            def version_probe(path: pathlib.Path) -> preflight_module.ProbeResult:
                observed_probe_paths.append(("version", path))
                self.assertNotEqual(path, installed.resolve())
                self.assertTrue(path.is_file())
                return preflight_module.ProbeResult(
                    0,
                    b"2.1.216 (Claude Code)\n",
                    b"",
                )

            def help_probe(path: pathlib.Path) -> preflight_module.ProbeResult:
                observed_probe_paths.append(("help", path))
                self.assertNotEqual(path, installed.resolve())
                self.assertTrue(path.is_file())
                return preflight_module.ProbeResult(0, self._supported_help(), b"")

            with (
                mock.patch.object(
                    preflight_module,
                    "_platform_key",
                    return_value="darwin-arm64",
                ),
                mock.patch.object(
                    preflight_module,
                    "verify_claude_release",
                    side_effect=release_verifier,
                ),
            ):
                value = preflight_module.preflight(
                    home=home,
                    version_probe=version_probe,
                    help_probe=help_probe,
                )

            self.assertEqual(value["classification"], "accepted")
            self.assertEqual(
                [kind for kind, _path in observed_probe_paths],
                ["version", "help"],
            )
            for _kind, path in observed_probe_paths:
                self.assertFalse(path.exists())

    def test_publisher_result_identity_must_match_selected_release_before_probe(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            candidate = root / "claude"
            other = root / "other-claude"
            self._write_candidate(candidate, version="2.1.216")
            self._write_candidate(other, version="2.1.216")
            resolved = candidate.resolve(strict=True)
            payload = resolved.read_bytes()
            source_identity = claude_provenance._stat_identity(
                resolved.stat(follow_symlinks=False)
            )
            expected_manifest, expected_signature = (
                claude_provenance.release_artifact_urls("2.1.216")
            )
            probe_called = False

            def forbidden_probe(_path: pathlib.Path) -> preflight_module.ProbeResult:
                nonlocal probe_called
                probe_called = True
                raise AssertionError("incoherent publisher result must not be probed")

            cases: dict[str, dict[str, object]] = {
                "path": {"executable": other.resolve()},
                "version": {"version": "2.1.215"},
                "platform": {"platform": "darwin-x64"},
                "binary": {"binary": "claude.exe"},
                "manifest": {"manifest_url": expected_manifest + ".other"},
                "signature": {"signature_url": expected_signature + ".other"},
            }
            for name, overrides in cases.items():
                with self.subTest(name=name):
                    executable = overrides.get("executable", resolved)
                    version = overrides.get("version", "2.1.216")
                    platform = overrides.get("platform", "darwin-arm64")
                    binary = overrides.get("binary", "claude")
                    manifest_url = overrides.get("manifest_url", expected_manifest)
                    signature_url = overrides.get(
                        "signature_url",
                        expected_signature,
                    )
                    assert isinstance(executable, pathlib.Path)
                    assert isinstance(version, str)
                    assert isinstance(platform, str)
                    assert isinstance(binary, str)
                    assert isinstance(manifest_url, str)
                    assert isinstance(signature_url, str)
                    verified = claude_provenance.VerifiedClaudeExecutable(
                        executable=executable,
                        artifact=claude_provenance.ClaudeReleaseArtifact(
                            version=version,
                            platform_key=platform,
                            binary=binary,
                            checksum=hashlib.sha256(payload).hexdigest(),
                            size=len(payload),
                        ),
                        manifest_url=manifest_url,
                        signature_url=signature_url,
                        gpg_path=pathlib.Path("/trusted/gpg"),
                        source_identity=source_identity,
                    )
                    with (
                        mock.patch.object(
                            preflight_module,
                            "_platform_key",
                            return_value="darwin-arm64",
                        ),
                        mock.patch.object(
                            preflight_module,
                            "verify_claude_release",
                            return_value=verified,
                        ),
                        self.assertRaises(claude_provenance.ClaudeProvenanceInvalid),
                    ):
                        preflight_module.verify_publisher_candidate(
                            resolved,
                            "2.1.216",
                            forbidden_probe,
                            forbidden_probe,
                        )

            self.assertFalse(probe_called)

    def test_unsafe_snapshot_metadata_is_inconclusive_not_version_mismatch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            exact = home / ".local/share/claude/versions/2.1.212"
            self._write_candidate(exact)
            payload = exact.read_bytes()
            resolved = exact.resolve(strict=True)
            manifest_url, signature_url = claude_provenance.release_artifact_urls(
                "2.1.212"
            )
            verified = claude_provenance.VerifiedClaudeExecutable(
                executable=resolved,
                artifact=claude_provenance.ClaudeReleaseArtifact(
                    version="2.1.212",
                    platform_key="darwin-arm64",
                    binary="claude",
                    checksum=hashlib.sha256(payload).hexdigest(),
                    size=len(payload),
                ),
                manifest_url=manifest_url,
                signature_url=signature_url,
                gpg_path=pathlib.Path("/trusted/gpg"),
                source_identity=claude_provenance._stat_identity(
                    resolved.stat(follow_symlinks=False)
                ),
            )

            with (
                mock.patch.object(
                    preflight_module,
                    "_platform_key",
                    return_value="darwin-arm64",
                ),
                mock.patch.object(
                    preflight_module,
                    "verify_claude_release",
                    return_value=verified,
                ),
                mock.patch.object(
                    preflight_module,
                    "materialize_verified_executable",
                    side_effect=claude_provenance.ClaudeProvenanceInvalid(
                        "unsafe snapshot metadata"
                    ),
                ),
            ):
                value = preflight_module.preflight(home=home)

            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "publisher-verification-inconclusive")

    def test_replacement_after_publisher_verification_never_reaches_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            exact = home / ".local/share/claude/versions/2.1.212"
            self._write_candidate(exact)
            original_payload = exact.read_bytes()
            probe_called = False

            def release_then_replace(
                executable: pathlib.Path,
                *,
                version: str,
                platform_key: str,
                gpg_temp_root: pathlib.Path,
            ) -> claude_provenance.VerifiedClaudeExecutable:
                del gpg_temp_root
                resolved = executable.resolve(strict=True)
                source_identity = claude_provenance._stat_identity(
                    resolved.stat(follow_symlinks=False)
                )
                replacement = root / "replacement"
                self._write_candidate(replacement)
                replacement.write_bytes(b"X" * len(original_payload))
                replacement.chmod(0o755)
                os.replace(replacement, resolved)
                manifest_url, signature_url = claude_provenance.release_artifact_urls(
                    version
                )
                return claude_provenance.VerifiedClaudeExecutable(
                    executable=resolved,
                    artifact=claude_provenance.ClaudeReleaseArtifact(
                        version=version,
                        platform_key=platform_key,
                        binary="claude",
                        checksum=hashlib.sha256(original_payload).hexdigest(),
                        size=len(original_payload),
                    ),
                    manifest_url=manifest_url,
                    signature_url=signature_url,
                    gpg_path=pathlib.Path("/trusted/gpg"),
                    source_identity=source_identity,
                )

            def forbidden_probe(_path: pathlib.Path) -> preflight_module.ProbeResult:
                nonlocal probe_called
                probe_called = True
                raise AssertionError("replaced candidate must not be probed")

            with (
                mock.patch.object(
                    preflight_module,
                    "_platform_key",
                    return_value="darwin-arm64",
                ),
                mock.patch.object(
                    preflight_module,
                    "verify_claude_release",
                    side_effect=release_then_replace,
                ),
            ):
                value = preflight_module.preflight(
                    home=home,
                    version_probe=forbidden_probe,
                )

            self.assertFalse(probe_called)
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "publisher-verification-inconclusive")

    def test_final_digest_revalidation_detects_stat_identity_collision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            exact = home / ".local/share/claude/versions/2.1.212"
            self._write_candidate(exact)
            original_identity = preflight_module._identity
            verified_identity: dict[str, int] = {}

            def rewrite_after_binding(
                path: pathlib.Path,
                release_version: str,
                _version_probe: preflight_module.VersionProbe,
                _help_probe: preflight_module.HelpProbe,
            ) -> preflight_module.VerifiedCandidate:
                before = path.stat(follow_symlinks=False)
                identity = original_identity(path)
                payload = path.read_bytes()
                replacement = bytes([payload[0] ^ 1]) + payload[1:]
                path.write_bytes(replacement)
                path.chmod(0o755)
                os.utime(
                    path,
                    ns=(before.st_atime_ns, before.st_mtime_ns),
                    follow_symlinks=False,
                )
                verified_identity.update(identity)
                manifest_url, signature_url = claude_provenance.release_artifact_urls(
                    release_version
                )
                return preflight_module.VerifiedCandidate(
                    resolved_path=path,
                    artifact=claude_provenance.ClaudeReleaseArtifact(
                        version=release_version,
                        platform_key="darwin-arm64",
                        binary="claude",
                        checksum=hashlib.sha256(payload).hexdigest(),
                        size=len(payload),
                    ),
                    identity=identity,
                    manifest_url=manifest_url,
                    signature_url=signature_url,
                    version_probe_result=preflight_module.ProbeResult(
                        0,
                        b"2.1.212 (Claude Code)\n",
                        b"",
                    ),
                    help_probe_result=preflight_module.ProbeResult(
                        0,
                        self._supported_help(),
                        b"",
                    ),
                )

            def colliding_identity(path: pathlib.Path) -> dict[str, int]:
                if verified_identity and path.resolve(strict=True) == exact.resolve():
                    return dict(verified_identity)
                return original_identity(path)

            with mock.patch.object(
                preflight_module,
                "_identity",
                side_effect=colliding_identity,
            ):
                value = preflight_module.preflight(
                    home=home,
                    verifier=rewrite_after_binding,
                )

            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "executable-identity-drift")

    def test_identity_drift_precedes_simultaneous_wrong_version_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            exact = home / ".local/share/claude/versions/2.1.212"
            self._write_candidate(exact)

            def replace_after_binding(
                path: pathlib.Path,
                release_version: str,
                _version_probe: preflight_module.VersionProbe,
                _help_probe: preflight_module.HelpProbe,
            ) -> preflight_module.VerifiedCandidate:
                identity = preflight_module._identity(path)
                replacement = root / "different-claude"
                self._write_candidate(replacement)
                os.replace(replacement, path)
                manifest_url, signature_url = claude_provenance.release_artifact_urls(
                    release_version
                )
                return preflight_module.VerifiedCandidate(
                    resolved_path=path,
                    artifact=claude_provenance.ClaudeReleaseArtifact(
                        version=release_version,
                        platform_key="darwin-arm64",
                        binary="claude",
                        checksum="a" * 64,
                        size=path.stat().st_size,
                    ),
                    identity=identity,
                    manifest_url=manifest_url,
                    signature_url=signature_url,
                    version_probe_result=preflight_module.ProbeResult(
                        0,
                        b"2.1.216 (Claude Code)\n",
                        b"",
                    ),
                    help_probe_result=preflight_module.ProbeResult(
                        0,
                        self._supported_help(),
                        b"",
                    ),
                )

            value = preflight_module.preflight(
                home=home,
                verifier=replace_after_binding,
            )

            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "executable-identity-drift")

    def test_invalid_publisher_provenance_is_not_reported_as_version_mismatch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            exact = home / ".local/share/claude/versions/2.1.212"
            self._write_candidate(exact)
            probe_called = False

            def invalid_publisher_provenance(
                _path: pathlib.Path,
                _release_version: str,
                _version_probe: preflight_module.VersionProbe,
                _help_probe: preflight_module.HelpProbe,
            ) -> preflight_module.VerifiedCandidate:
                raise claude_provenance.ClaudeProvenanceInvalid(
                    "synthetic invalid signature"
                )

            def forbidden_probe(_path: pathlib.Path) -> preflight_module.ProbeResult:
                nonlocal probe_called
                probe_called = True
                raise AssertionError("probe must not run")

            value = preflight_module.preflight(
                home=home,
                verifier=invalid_publisher_provenance,
                version_probe=forbidden_probe,
            )

            self.assertFalse(probe_called)
            self.assertEqual(value["classification"], "blocked")
            self.assertEqual(value["reason"], "publisher-verification-failed")
            self.assertNotEqual(value["reason"], "signed-version-identity-mismatch")

    def test_unexpected_verifier_error_is_bounded_inconclusive_without_probe(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            exact = home / ".local/share/claude/versions/2.1.212"
            self._write_candidate(exact)
            probe_called = False

            def broken_verifier(
                _path: pathlib.Path,
                _release_version: str,
                _version_probe: preflight_module.VersionProbe,
                _help_probe: preflight_module.HelpProbe,
            ) -> preflight_module.VerifiedCandidate:
                raise RuntimeError("synthetic unexpected verifier failure")

            def forbidden_probe(_path: pathlib.Path) -> preflight_module.ProbeResult:
                nonlocal probe_called
                probe_called = True
                raise AssertionError("probe must not run")

            value = preflight_module.preflight(
                home=home,
                verifier=broken_verifier,
                version_probe=forbidden_probe,
            )
            payload = preflight_module._machine_json(value)

            self.assertFalse(probe_called)
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "publisher-verification-inconclusive")
            self.assertEqual(payload.count(b"\n"), 1)
            self.assertLessEqual(
                len(payload), preflight_module.MACHINE_OUTPUT_LIMIT_BYTES
            )
            self.assertEqual(json.loads(payload), value)

    def test_linux_identity_inspection_failure_is_inconclusive_without_probe(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            exact = home / ".local/share/claude/versions/2.1.212"
            self._write_candidate(exact)
            probe_called = False

            def forbidden_probe(_path: pathlib.Path) -> preflight_module.ProbeResult:
                nonlocal probe_called
                probe_called = True
                raise AssertionError("probe must not run")

            with (
                mock.patch.object(preflight_module.sys, "platform", "linux"),
                mock.patch.object(claude_linux, "detect_host", return_value=object()),
                mock.patch.object(
                    claude_linux,
                    "validate_claude_executable",
                    side_effect=claude_linux.LinuxRuntimeInspectionInconclusive(
                        "synthetic identity drift"
                    ),
                ),
            ):
                value = preflight_module.preflight(
                    home=home,
                    verifier=preflight_module.verify_publisher_candidate,
                    version_probe=forbidden_probe,
                )

            self.assertFalse(probe_called)
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    def test_darwin_header_io_failure_is_inconclusive_without_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            exact = home / ".local/share/claude/versions/2.1.212"
            self._write_candidate(exact)
            probe_called = False

            def forbidden_probe(_path: pathlib.Path) -> preflight_module.ProbeResult:
                nonlocal probe_called
                probe_called = True
                raise AssertionError("probe must not run")

            real_open = os.open
            resolved_exact = exact.resolve()

            def fail_candidate_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
                if pathlib.Path(path) == resolved_exact:
                    raise OSError("synthetic temporary read failure")
                return real_open(path, flags, *args, **kwargs)

            with (
                mock.patch.object(preflight_module.sys, "platform", "darwin"),
                mock.patch.object(
                    preflight_module.os,
                    "open",
                    side_effect=fail_candidate_open,
                ),
            ):
                value = preflight_module.preflight(
                    home=home,
                    verifier=preflight_module.verify_publisher_candidate,
                    version_probe=forbidden_probe,
                )

            self.assertFalse(probe_called)
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    @unittest.skipUnless(
        hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
        "requires POSIX FIFO support",
    )
    def test_preflight_rejects_fifo_replacement_after_stat_without_blocking(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate = pathlib.Path(temporary) / "claude"
            self._write_candidate(candidate)
            resolved_candidate = candidate.resolve()
            replacement = candidate.with_name("claude.fifo")
            os.mkfifo(replacement, mode=0o700)
            real_open = os.open
            requested_flags: list[int] = []
            swapped = False
            values: list[dict[str, object]] = []
            failures: list[BaseException] = []

            def swap_before_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
                nonlocal swapped
                if pathlib.Path(path) == resolved_candidate and not swapped:
                    swapped = True
                    requested_flags.append(flags)
                    os.replace(replacement, candidate)
                return real_open(path, flags, *args, **kwargs)

            def run_preflight() -> None:
                try:
                    values.append(
                        preflight_module.preflight(
                            explicit_path=candidate,
                            explicit_version="2.1.212",
                        )
                    )
                except BaseException as error:
                    failures.append(error)

            worker = threading.Thread(target=run_preflight, daemon=True)
            with (
                mock.patch.object(preflight_module.sys, "platform", "darwin"),
                mock.patch.object(
                    preflight_module.os,
                    "open",
                    side_effect=swap_before_open,
                ),
            ):
                worker.start()
                worker.join(timeout=1.0)
                if worker.is_alive():
                    rescue = real_open(candidate, os.O_RDWR | os.O_NONBLOCK)
                    os.close(rescue)
                    worker.join(timeout=1.0)

            self.assertFalse(worker.is_alive(), "candidate FIFO open blocked preflight")
            self.assertFalse(failures)
            self.assertTrue(swapped)
            self.assertTrue(requested_flags[0] & os.O_NONBLOCK)
            self.assertEqual(values[0]["classification"], "inconclusive")
            self.assertEqual(
                values[0]["reason"],
                "candidate-inspection-inconclusive",
            )

    def test_symlinked_provenance_parent_is_canonicalized_before_validation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            real_parent = root / "real-provenance-root"
            real_parent.mkdir(mode=0o700)
            alias_parent = root / "provenance-root-alias"
            alias_parent.symlink_to(real_parent, target_is_directory=True)
            candidate = root / "claude"
            self._write_candidate(candidate)
            observed_roots: list[pathlib.Path] = []

            def release_verifier(
                executable: pathlib.Path,
                *,
                version: str,
                platform_key: str,
                gpg_temp_root: pathlib.Path,
            ) -> claude_provenance.VerifiedClaudeExecutable:
                self.assertEqual(version, "2.1.212")
                self.assertEqual(platform_key, "darwin-arm64")
                trust = claude_provenance._resolve_trusted_gpg_temp_root(
                    gpg_temp_root,
                    validator=None,
                )
                self.assertEqual(trust.requested, trust.resolved)
                observed_roots.append(gpg_temp_root)
                resolved = executable.resolve(strict=True)
                payload = resolved.read_bytes()
                artifact = claude_provenance.ClaudeReleaseArtifact(
                    version=version,
                    platform_key=platform_key,
                    binary="claude",
                    checksum=hashlib.sha256(payload).hexdigest(),
                    size=len(payload),
                )
                manifest_url, signature_url = claude_provenance.release_artifact_urls(
                    version
                )
                return claude_provenance.VerifiedClaudeExecutable(
                    executable=resolved,
                    artifact=artifact,
                    manifest_url=manifest_url,
                    signature_url=signature_url,
                    gpg_path=pathlib.Path("/trusted/gpg"),
                    source_identity=claude_provenance._stat_identity(
                        resolved.stat(follow_symlinks=False)
                    ),
                )

            with (
                mock.patch.object(
                    preflight_module,
                    "PROVENANCE_TEMP_ROOT",
                    alias_parent,
                ),
                mock.patch.object(
                    preflight_module,
                    "_platform_key",
                    return_value="darwin-arm64",
                ),
                mock.patch.object(
                    preflight_module,
                    "verify_claude_release",
                    side_effect=release_verifier,
                ),
            ):
                verified = preflight_module.verify_publisher_candidate(
                    candidate,
                    "2.1.212",
                    lambda _path: preflight_module.ProbeResult(
                        0,
                        b"2.1.212 (Claude Code)\n",
                        b"",
                    ),
                    lambda _path: preflight_module.ProbeResult(
                        0,
                        self._supported_help(),
                        b"",
                    ),
                )

            self.assertEqual(verified.resolved_path, candidate.resolve())
            self.assertEqual(len(observed_roots), 1)
            self.assertEqual(observed_roots[0], observed_roots[0].resolve())
            self.assertEqual(observed_roots[0].parent, real_parent.resolve())

    def test_unresolvable_provenance_parent_is_inconclusive_before_execution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            exact = home / ".local/share/claude/versions/2.1.212"
            self._write_candidate(exact)
            missing_parent = root / "missing-provenance-root"
            probe_called = False

            def forbidden_probe(_path: pathlib.Path) -> preflight_module.ProbeResult:
                nonlocal probe_called
                probe_called = True
                raise AssertionError("probe must not run")

            with (
                mock.patch.object(
                    preflight_module,
                    "PROVENANCE_TEMP_ROOT",
                    missing_parent,
                ),
                mock.patch.object(
                    preflight_module,
                    "_platform_key",
                    return_value="darwin-arm64",
                ),
                mock.patch.object(
                    preflight_module,
                    "verify_claude_release",
                ) as release_verifier,
            ):
                value = preflight_module.preflight(
                    home=home,
                    verifier=preflight_module.verify_publisher_candidate,
                    version_probe=forbidden_probe,
                )

            release_verifier.assert_not_called()
            self.assertFalse(probe_called)
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    def test_public_main_contains_unexpected_error_as_one_json_object(self) -> None:
        output = types.SimpleNamespace(value="")

        def write(payload: str) -> None:
            output.value += payload

        destination = types.SimpleNamespace(write=write)
        with mock.patch.object(
            preflight_module,
            "preflight",
            side_effect=RuntimeError("synthetic internal failure"),
        ):
            returncode = preflight_module.main(argv=(), stdout=destination)

        self.assertEqual(returncode, 2)
        self.assertEqual(output.value.count("\n"), 1)
        self.assertEqual(
            json.loads(output.value),
            {
                "classification": "inconclusive",
                "compatible_version_range": ">=2.1.211,<3.0.0",
                "reason": "preflight-internal-error",
            },
        )

    def test_public_main_prefers_explicit_selection_home_over_ambient_home(
        self,
    ) -> None:
        selected_home = pathlib.Path("/trusted/account-home")
        destination = types.SimpleNamespace(write=lambda _payload: None)
        with (
            mock.patch.dict(
                os.environ,
                {"HOME": "/attacker/ambient-home"},
                clear=True,
            ),
            mock.patch.object(
                preflight_module,
                "preflight",
                return_value={
                    "classification": "blocked",
                    "reason": "compatible-version-unavailable",
                },
            ) as preflight,
        ):
            returncode = preflight_module.main(
                argv=(),
                stdout=destination,
                selection_home=selected_home,
            )

        self.assertEqual(returncode, 1)
        preflight.assert_called_once_with(
            explicit_path=None,
            explicit_version=None,
            home=selected_home,
        )

    def test_invalid_arguments_return_one_json_object_without_stderr(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            completed = self._run(
                home=root,
                path="",
                args=("--unknown",),
            )

            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stderr, "")
            self.assertEqual(completed.stdout.count("\n"), 1)
            self.assertEqual(
                json.loads(completed.stdout),
                {
                    "classification": "inconclusive",
                    "compatible_version_range": ">=2.1.211,<3.0.0",
                    "reason": "invalid-arguments",
                },
            )


if __name__ == "__main__":
    unittest.main()
