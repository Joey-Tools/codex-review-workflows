from __future__ import annotations

import errno
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
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
)
from review_runtime import named_claude_preflight as preflight_module  # noqa: E402


EXPECTED_SUPPORTED_VERSION_RANGE = {
    "minimum": "2.1.211",
    "maximum_exclusive": "3.0.0",
}


def _supported_help() -> str:
    safe_mode = (
        "Start with all customizations (CLAUDE.md, skills, plugins, hooks, MCP "
        "servers, custom commands and agents, output styles, workflows, custom "
        "themes, keybindings, and more) disabled. Admin-managed (policy) settings "
        "still apply. Auth, model selection, built-in tools, and permissions work "
        "normally. Sets CLAUDE_CODE_SAFE_MODE=1."
    )
    lines = ["Usage: claude [options]", "", "Options:"]
    for option in claude_capabilities.CLAUDE_REQUIRED_OPTIONS:
        if option == "--safe-mode":
            description = safe_mode
        elif option == "--permission-mode":
            description = "Permission mode (choices: default, dontAsk, plan)."
        else:
            description = "Supported option."
        lines.append(f"  {option} <value>  {description}")
    return "\n".join(lines) + "\n"


class NamedClaudePreflightTest(unittest.TestCase):
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
            lines.append(f"printf 'executed\\n' >> {marker}")
        lines.extend((f"printf '{version} (Claude Code)\\n'", "exit 0"))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        path.chmod(0o755)

    def _write_active_candidate(
        self,
        home: pathlib.Path,
        *,
        version: str = "2.1.212",
        marker: pathlib.Path | None = None,
    ) -> pathlib.Path:
        installed = home / f".local/share/claude/versions/{version}"
        self._write_candidate(installed, marker=marker, version=version)
        active = home / ".local/bin/claude"
        active.parent.mkdir(parents=True, exist_ok=True)
        active.symlink_to(installed)
        return installed

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
        *,
        version: str = "2.1.212",
        probe_result: preflight_module.ProbeResult | None = None,
        capabilities: claude_capabilities.ClaudeCapabilities | None = None,
    ) -> preflight_module.VerifiedCandidate:
        resolved = path.resolve(strict=True)
        return preflight_module.VerifiedCandidate(
            resolved_path=resolved,
            version=version,
            platform_key="darwin-arm64",
            checksum=hashlib.sha256(resolved.read_bytes()).hexdigest(),
            artifact_size=resolved.stat().st_size,
            identity=preflight_module._identity(resolved),
            probe_result=probe_result
            or preflight_module.ProbeResult(
                0,
                f"{version} (Claude Code)\n".encode(),
                b"",
            ),
            capabilities=capabilities
            or claude_capabilities.validate_claude_capabilities(
                f"{version} (Claude Code)\n",
                _supported_help(),
                expected_version=version,
            ),
        )

    def _verified_with_probes(
        self,
        path: pathlib.Path,
        version: str,
        version_probe: preflight_module.VersionProbe,
        capability_probe: preflight_module.CapabilityProbe,
    ) -> preflight_module.VerifiedCandidate:
        version_result = version_probe(path)
        capability_result = capability_probe(path)
        capabilities = claude_capabilities.validate_claude_capabilities(
            version_result.stdout.decode("utf-8", errors="strict"),
            capability_result.stdout.decode("utf-8", errors="strict"),
            expected_version=version,
        )
        return self._verified(
            path,
            version=version,
            probe_result=version_result,
            capabilities=capabilities,
        )

    def _successful_capability_probe(
        self,
        _path: pathlib.Path,
    ) -> preflight_module.ProbeResult:
        return preflight_module.ProbeResult(0, _supported_help().encode(), b"")

    def _verified_release(
        self,
        executable: pathlib.Path,
        *,
        version: str,
        platform_key: str,
        gpg_temp_root: pathlib.Path,
    ) -> claude_provenance.VerifiedClaudeExecutable:
        del gpg_temp_root
        resolved = executable.resolve(strict=True)
        payload = resolved.read_bytes()
        return claude_provenance.VerifiedClaudeExecutable(
            executable=resolved,
            artifact=claude_provenance.ClaudeReleaseArtifact(
                version=version,
                platform_key=platform_key,
                binary="claude",
                checksum=hashlib.sha256(payload).hexdigest(),
                size=len(payload),
            ),
            manifest_url="https://downloads.claude.ai/manifest.json",
            signature_url="https://downloads.claude.ai/manifest.json.sig",
            gpg_path=pathlib.Path("/trusted/gpg"),
            source_identity=claude_provenance._stat_identity(
                resolved.stat(follow_symlinks=False)
            ),
        )

    def test_active_2_1_216_is_accepted_after_publisher_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            marker = root / "active-invocations"
            installed = self._write_active_candidate(
                home,
                version="2.1.216",
                marker=marker,
            )
            calls: list[tuple[str, pathlib.Path]] = []

            def verifier(
                path: pathlib.Path,
                version: str,
                version_probe: preflight_module.VersionProbe,
                capability_probe: preflight_module.CapabilityProbe,
            ) -> preflight_module.VerifiedCandidate:
                calls.append(("verify", path))
                self.assertEqual(version, "2.1.216")
                return self._verified_with_probes(
                    path,
                    version,
                    version_probe,
                    capability_probe,
                )

            def version_probe(path: pathlib.Path) -> preflight_module.ProbeResult:
                calls.append(("version", path))
                return preflight_module.ProbeResult(
                    0,
                    b"2.1.216 (Claude Code)\n",
                    b"",
                )

            def capability_probe(path: pathlib.Path) -> preflight_module.ProbeResult:
                calls.append(("capabilities", path))
                return self._successful_capability_probe(path)

            value = preflight_module.preflight(
                home=home,
                verifier=verifier,
                version_probe=version_probe,
                capability_probe=capability_probe,
            )

            self.assertEqual(value["classification"], "accepted")
            self.assertEqual(value["reason"], "supported-version-selected")
            self.assertEqual(value["observed_version"], "2.1.216")
            self.assertEqual(value["source"], "active-installed")
            self.assertEqual(
                value["supported_version_range"], EXPECTED_SUPPORTED_VERSION_RANGE
            )
            self.assertEqual(
                value["capability_verification"],
                {
                    "required_options": list(
                        claude_capabilities.CLAUDE_REQUIRED_OPTIONS
                    ),
                    "safe_mode": "accepted",
                },
            )
            self.assertEqual(
                [name for name, _path in calls],
                ["verify", "version", "capabilities"],
            )
            self.assertTrue(all(path == installed.resolve() for _name, path in calls))
            self.assertFalse(marker.exists())

    def test_unsupported_version_loses_to_descriptor_identity_drift(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            marker = root / "active-invocations"
            self._write_active_candidate(
                home,
                version="3.0.0",
                marker=marker,
            )
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

    def test_explicit_unversioned_path_uses_supported_version_hint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            explicit = root / "claude"
            self._write_candidate(explicit, version="2.1.216")
            calls: list[tuple[str, pathlib.Path]] = []

            def verifier(
                path: pathlib.Path,
                version: str,
                version_probe: preflight_module.VersionProbe,
                capability_probe: preflight_module.CapabilityProbe,
            ) -> preflight_module.VerifiedCandidate:
                calls.append(("verify", path))
                return self._verified_with_probes(
                    path,
                    version,
                    version_probe,
                    capability_probe,
                )

            def version_probe(path: pathlib.Path) -> preflight_module.ProbeResult:
                calls.append(("version", path))
                return preflight_module.ProbeResult(
                    0,
                    b"2.1.216 (Claude Code)\n",
                    b"",
                )

            def capability_probe(path: pathlib.Path) -> preflight_module.ProbeResult:
                calls.append(("capabilities", path))
                return self._successful_capability_probe(path)

            value = preflight_module.preflight(
                explicit_path=explicit,
                explicit_version="2.1.216",
                verifier=verifier,
                version_probe=version_probe,
                capability_probe=capability_probe,
            )

            self.assertEqual(value["classification"], "accepted")
            self.assertEqual(value["source"], "explicit-override")
            self.assertEqual(value["resolved_path"], str(explicit.resolve()))
            self.assertEqual(value["observed_version"], "2.1.216")
            self.assertEqual(
                [name for name, _path in calls],
                ["verify", "version", "capabilities"],
            )

    def test_out_of_range_explicit_override_does_not_fall_back_or_execute(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            explicit_marker = root / "explicit-invocations"
            active_marker = root / "active-invocations"
            explicit = root / "claude"
            self._write_candidate(
                explicit,
                marker=explicit_marker,
                version="3.0.0",
            )
            self._write_active_candidate(
                home,
                version="2.1.216",
                marker=active_marker,
            )

            completed = self._run(
                home=home,
                path="",
                args=(
                    "--claude-path",
                    str(explicit),
                    "--claude-version",
                    "3.0.0",
                ),
            )
            value = json.loads(completed.stdout)

            self.assertEqual(completed.returncode, 1)
            self.assertEqual(value["reason"], "unsupported-version")
            self.assertEqual(value["declared_version"], "3.0.0")
            self.assertEqual(value["source"], "explicit-override")
            self.assertEqual(
                value["supported_version_range"], EXPECTED_SUPPORTED_VERSION_RANGE
            )
            self.assertFalse(explicit_marker.exists())
            self.assertFalse(active_marker.exists())

    def test_observed_version_must_match_publisher_verified_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary) / "home"
            self._write_active_candidate(home, version="2.1.216")

            def verifier(
                path: pathlib.Path,
                version: str,
                _version_probe: preflight_module.VersionProbe,
                _capability_probe: preflight_module.CapabilityProbe,
            ) -> preflight_module.VerifiedCandidate:
                return self._verified(
                    path,
                    version=version,
                    probe_result=preflight_module.ProbeResult(
                        0,
                        b"2.1.215 (Claude Code)\n",
                        b"",
                    ),
                )

            value = preflight_module.preflight(home=home, verifier=verifier)

            self.assertEqual(value["classification"], "blocked")
            self.assertEqual(value["reason"], "version-mismatch")
            self.assertEqual(value["observed_version"], "2.1.215")
            self.assertEqual(
                value["publisher_verification"]["version"],
                "2.1.216",
            )

    def test_present_active_path_that_is_a_script_is_never_executed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            marker = root / "script-invocations"
            self._write_active_candidate(home, marker=marker)

            completed = self._run(home=home, path="")
            value = json.loads(completed.stdout)

            self.assertEqual(completed.returncode, 1)
            self.assertEqual(value["classification"], "blocked")
            self.assertEqual(value["reason"], "supported-version-unavailable")
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

            self.assertEqual(value["reason"], "supported-version-unavailable")
            self.assertFalse(marker.exists())

    def test_candidate_presence_io_failure_stops_before_lower_priority_fallback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            active = home / preflight_module.ACTIVE_HOME_RELATIVE_PATH
            lower_priority = root / "trusted-bin/claude"
            self._write_candidate(lower_priority)
            verifier_called = False
            original_lstat = pathlib.Path.lstat

            def fail_active_lstat(
                path: pathlib.Path,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                if path == active:
                    raise OSError(errno.EIO, "synthetic candidate inspection failure")
                return original_lstat(path, *args, **kwargs)  # type: ignore[arg-type]

            def forbidden_verifier(
                _path: pathlib.Path,
                _version: str,
                _version_probe: preflight_module.VersionProbe,
                _capability_probe: preflight_module.CapabilityProbe,
            ) -> preflight_module.VerifiedCandidate:
                nonlocal verifier_called
                verifier_called = True
                raise AssertionError("lower-priority candidate must not be verified")

            with (
                mock.patch.object(
                    pathlib.Path,
                    "lstat",
                    autospec=True,
                    side_effect=fail_active_lstat,
                ),
                mock.patch.object(
                    preflight_module,
                    "TRUSTED_ACTIVE_PATHS",
                    (lower_priority,),
                ),
            ):
                value = preflight_module.preflight(
                    home=home,
                    verifier=forbidden_verifier,
                )

            self.assertFalse(verifier_called)
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "candidate-inspection-inconclusive")

    def test_observed_automatic_candidate_disappearance_is_inconclusive(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            active = home / ".local/bin/claude"
            self._write_candidate(active)
            lower_priority = root / "trusted-bin/claude"
            self._write_candidate(lower_priority)
            original_exists = preflight_module._candidate_exists
            observed = False

            def observe_then_remove(path: pathlib.Path) -> bool:
                nonlocal observed
                if path == active and not observed:
                    observed = True
                    path.unlink()
                    return True
                return original_exists(path)

            with (
                mock.patch.object(
                    preflight_module,
                    "_candidate_exists",
                    side_effect=observe_then_remove,
                ),
                mock.patch.object(
                    preflight_module,
                    "TRUSTED_ACTIVE_PATHS",
                    (lower_priority,),
                ),
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
            self.assertEqual(value["source"], "active-installed")

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

    def test_missing_supported_version_is_stable_blocked_json(self) -> None:
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
                    "reason": "supported-version-unavailable",
                    "source": "explicit-override",
                    "supported_version_range": EXPECTED_SUPPORTED_VERSION_RANGE,
                },
            )

    def test_probe_uses_fixed_credential_free_environment_and_no_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            repo = root / "repo-with-private-context"
            repo.mkdir()
            installed = self._write_active_candidate(home, version="2.1.216")
            observed: list[tuple[tuple[object, ...], dict[str, object]]] = []

            def bounded_capture(*args, **kwargs):  # type: ignore[no-untyped-def]
                observed.append((args, kwargs))
                command = args[0]
                assert isinstance(command, tuple)
                stdout = (
                    b"2.1.216 (Claude Code)\n"
                    if command[-1] == "--version"
                    else _supported_help().encode()
                )
                return types.SimpleNamespace(
                    returncode=0,
                    stdout=bytearray(stdout),
                    stderr=bytearray(),
                )

            with mock.patch.object(
                preflight_module,
                "run_bounded_capture",
                side_effect=bounded_capture,
            ):
                value = preflight_module.preflight(
                    home=home,
                    verifier=self._verified_with_probes,
                    version_probe=preflight_module.probe_verified_version,
                    capability_probe=preflight_module.probe_verified_capabilities,
                )

            self.assertEqual(value["classification"], "accepted")
            self.assertEqual(len(observed), 2)
            self.assertEqual(
                [args for args, _kwargs in observed],
                [
                    ((str(installed.resolve()), "--version"),),
                    ((str(installed.resolve()), "--help"),),
                ],
            )
            for args, kwargs in observed:
                self.assertEqual(kwargs["cwd"], pathlib.Path("/"))
                self.assertEqual(
                    kwargs["env"],
                    dict(preflight_module.VERSION_PROBE_ENV),
                )
                self.assertIsNone(kwargs["stdin"])
                self.assertNotIn("ANTHROPIC_API_KEY", kwargs["env"])
                self.assertNotIn("CLAUDE_CODE_OAUTH_TOKEN", kwargs["env"])
                self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
                command = args[0]
                assert isinstance(command, tuple)
                expected_limit = (
                    preflight_module.VERSION_PROBE_OUTPUT_LIMIT_BYTES
                    if command[-1] == "--version"
                    else preflight_module.CAPABILITY_PROBE_OUTPUT_LIMIT_BYTES
                )
                self.assertEqual(kwargs["stdout_limit_bytes"], expected_limit)
                self.assertEqual(kwargs["stderr_limit_bytes"], expected_limit)
            self.assertNotIn(str(repo), repr(observed))

    def test_default_verifier_probes_private_snapshot_not_candidate_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            installed = self._write_active_candidate(home, version="2.1.216")
            payload = installed.read_bytes()
            observed_probe_paths: list[pathlib.Path] = []
            events: list[str] = []

            def release_verifier(
                executable: pathlib.Path,
                *,
                version: str,
                platform_key: str,
                gpg_temp_root: pathlib.Path,
            ) -> claude_provenance.VerifiedClaudeExecutable:
                del gpg_temp_root
                resolved = executable.resolve(strict=True)
                self.assertEqual(version, "2.1.216")
                events.append("publisher")
                return claude_provenance.VerifiedClaudeExecutable(
                    executable=resolved,
                    artifact=claude_provenance.ClaudeReleaseArtifact(
                        version=version,
                        platform_key=platform_key,
                        binary="claude",
                        checksum=hashlib.sha256(payload).hexdigest(),
                        size=len(payload),
                    ),
                    manifest_url="https://downloads.claude.ai/manifest.json",
                    signature_url="https://downloads.claude.ai/manifest.json.sig",
                    gpg_path=pathlib.Path("/trusted/gpg"),
                    source_identity=claude_provenance._stat_identity(
                        resolved.stat(follow_symlinks=False)
                    ),
                )

            def version_probe(path: pathlib.Path) -> preflight_module.ProbeResult:
                events.append("version")
                observed_probe_paths.append(path)
                self.assertNotEqual(path, installed.resolve())
                self.assertTrue(path.is_file())
                return preflight_module.ProbeResult(
                    0,
                    b"2.1.216 (Claude Code)\n",
                    b"",
                )

            def capability_probe(path: pathlib.Path) -> preflight_module.ProbeResult:
                events.append("capabilities")
                observed_probe_paths.append(path)
                self.assertNotEqual(path, installed.resolve())
                self.assertTrue(path.is_file())
                return self._successful_capability_probe(path)

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
                    capability_probe=capability_probe,
                )

            self.assertEqual(value["classification"], "accepted")
            self.assertEqual(events, ["publisher", "version", "capabilities"])
            self.assertEqual(len(observed_probe_paths), 2)
            self.assertEqual(observed_probe_paths[0], observed_probe_paths[1])
            self.assertTrue(all(not path.exists() for path in observed_probe_paths))

    def test_default_verifier_blocks_stable_wrong_version_without_help(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary) / "home"
            self._write_active_candidate(home, version="2.1.216")
            help_called = False

            def forbidden_help(_path: pathlib.Path) -> preflight_module.ProbeResult:
                nonlocal help_called
                help_called = True
                raise AssertionError("wrong version must stop before help")

            with (
                mock.patch.object(
                    preflight_module,
                    "_platform_key",
                    return_value="darwin-arm64",
                ),
                mock.patch.object(
                    preflight_module,
                    "verify_claude_release",
                    side_effect=self._verified_release,
                ),
            ):
                value = preflight_module.preflight(
                    home=home,
                    version_probe=lambda _path: preflight_module.ProbeResult(
                        0,
                        b"2.1.215 (Claude Code)\n",
                        b"",
                    ),
                    capability_probe=forbidden_help,
                )

            self.assertFalse(help_called)
            self.assertEqual(value["classification"], "blocked")
            self.assertEqual(value["reason"], "version-mismatch")
            self.assertEqual(value["observed_version"], "2.1.215")

    def test_default_verifier_rejects_malformed_version_without_help(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary) / "home"
            self._write_active_candidate(home, version="2.1.216")
            help_called = False

            def forbidden_help(_path: pathlib.Path) -> preflight_module.ProbeResult:
                nonlocal help_called
                help_called = True
                raise AssertionError("malformed version must stop before help")

            with (
                mock.patch.object(
                    preflight_module,
                    "_platform_key",
                    return_value="darwin-arm64",
                ),
                mock.patch.object(
                    preflight_module,
                    "verify_claude_release",
                    side_effect=self._verified_release,
                ),
            ):
                value = preflight_module.preflight(
                    home=home,
                    version_probe=lambda _path: preflight_module.ProbeResult(
                        0,
                        b"Claude Code 2.1.216\n",
                        b"",
                    ),
                    capability_probe=forbidden_help,
                )

            self.assertFalse(help_called)
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "version-probe-inconclusive")

    def test_default_verifier_source_drift_precedes_invalid_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            installed = self._write_active_candidate(home, version="2.1.216")
            help_called = False

            def mutate_source(_path: pathlib.Path) -> preflight_module.ProbeResult:
                installed.write_bytes(b"X" * installed.stat().st_size)
                installed.chmod(0o755)
                return preflight_module.ProbeResult(0, b"invalid\n", b"")

            def forbidden_help(_path: pathlib.Path) -> preflight_module.ProbeResult:
                nonlocal help_called
                help_called = True
                raise AssertionError("source drift must stop before help")

            with (
                mock.patch.object(
                    preflight_module,
                    "_platform_key",
                    return_value="darwin-arm64",
                ),
                mock.patch.object(
                    preflight_module,
                    "verify_claude_release",
                    side_effect=self._verified_release,
                ),
            ):
                value = preflight_module.preflight(
                    home=home,
                    version_probe=mutate_source,
                    capability_probe=forbidden_help,
                )

            self.assertFalse(help_called)
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "executable-identity-drift")

    def test_missing_or_changed_capability_option_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary) / "home"
            self._write_active_candidate(home, version="2.1.216")
            missing_settings = "\n".join(
                line
                for line in _supported_help().splitlines()
                if not line.startswith("  --settings ")
            )
            invalid_help = {
                "missing-option": missing_settings + "\n",
                "changed-permission-mode": _supported_help().replace(
                    "choices: default, dontAsk, plan",
                    "choices: default, plan",
                ),
            }

            for case, help_text in invalid_help.items():
                with (
                    self.subTest(case=case),
                    mock.patch.object(
                        preflight_module,
                        "_platform_key",
                        return_value="darwin-arm64",
                    ),
                    mock.patch.object(
                        preflight_module,
                        "verify_claude_release",
                        side_effect=self._verified_release,
                    ),
                ):
                    value = preflight_module.preflight(
                        home=home,
                        version_probe=lambda _path: preflight_module.ProbeResult(
                            0,
                            b"2.1.216 (Claude Code)\n",
                            b"",
                        ),
                        capability_probe=lambda _path, output=help_text: (
                            preflight_module.ProbeResult(0, output.encode(), b"")
                        ),
                    )

                self.assertEqual(value["classification"], "blocked")
                self.assertEqual(value["reason"], "capability-contract-mismatch")

    def test_capability_probe_failures_are_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary) / "home"
            self._write_active_candidate(home, version="2.1.216")

            def io_failure(_path: pathlib.Path) -> preflight_module.ProbeResult:
                raise OSError(errno.EIO, "synthetic help probe failure")

            cases: dict[str, preflight_module.CapabilityProbe] = {
                "io": io_failure,
                "nonzero": lambda _path: preflight_module.ProbeResult(
                    7,
                    _supported_help().encode(),
                    b"",
                ),
                "invalid-utf8": lambda _path: preflight_module.ProbeResult(
                    0,
                    b"\xff",
                    b"",
                ),
            }
            for case, capability_probe in cases.items():
                with (
                    self.subTest(case=case),
                    mock.patch.object(
                        preflight_module,
                        "_platform_key",
                        return_value="darwin-arm64",
                    ),
                    mock.patch.object(
                        preflight_module,
                        "verify_claude_release",
                        side_effect=self._verified_release,
                    ),
                ):
                    value = preflight_module.preflight(
                        home=home,
                        version_probe=lambda _path: preflight_module.ProbeResult(
                            0,
                            b"2.1.216 (Claude Code)\n",
                            b"",
                        ),
                        capability_probe=capability_probe,
                    )

                self.assertEqual(value["classification"], "inconclusive")
                self.assertEqual(value["reason"], "capability-probe-inconclusive")

    def test_snapshot_change_during_capability_probe_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary) / "home"
            installed = self._write_active_candidate(home, version="2.1.216")
            observed_snapshot: pathlib.Path | None = None

            def mutate_snapshot(path: pathlib.Path) -> preflight_module.ProbeResult:
                nonlocal observed_snapshot
                observed_snapshot = path
                self.assertNotEqual(path, installed.resolve())
                payload = path.read_bytes()
                path.chmod(0o700)
                path.write_bytes(bytes([payload[0] ^ 1]) + payload[1:])
                path.chmod(0o500)
                return self._successful_capability_probe(path)

            with (
                mock.patch.object(
                    preflight_module,
                    "_platform_key",
                    return_value="darwin-arm64",
                ),
                mock.patch.object(
                    preflight_module,
                    "verify_claude_release",
                    side_effect=self._verified_release,
                ),
            ):
                value = preflight_module.preflight(
                    home=home,
                    version_probe=lambda _path: preflight_module.ProbeResult(
                        0,
                        b"2.1.216 (Claude Code)\n",
                        b"",
                    ),
                    capability_probe=mutate_snapshot,
                )

            self.assertIsNotNone(observed_snapshot)
            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "executable-identity-drift")

    def test_snapshot_drift_precedes_invalid_capability_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary) / "home"
            installed = self._write_active_candidate(home, version="2.1.216")

            def mutate_snapshot(path: pathlib.Path) -> preflight_module.ProbeResult:
                self.assertNotEqual(path, installed.resolve())
                path.chmod(0o700)
                path.write_bytes(b"X" * path.stat().st_size)
                path.chmod(0o500)
                return preflight_module.ProbeResult(
                    0,
                    b"Usage: claude [options]\n",
                    b"",
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
                    side_effect=self._verified_release,
                ),
            ):
                value = preflight_module.preflight(
                    home=home,
                    version_probe=lambda _path: preflight_module.ProbeResult(
                        0,
                        b"2.1.216 (Claude Code)\n",
                        b"",
                    ),
                    capability_probe=mutate_snapshot,
                )

            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "executable-identity-drift")

    def test_source_drift_precedes_invalid_capability_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary) / "home"
            installed = self._write_active_candidate(home, version="2.1.216")

            def mutate_source(_path: pathlib.Path) -> preflight_module.ProbeResult:
                installed.write_bytes(b"X" * installed.stat().st_size)
                installed.chmod(0o755)
                return preflight_module.ProbeResult(
                    0,
                    b"Usage: claude [options]\n",
                    b"",
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
                    side_effect=self._verified_release,
                ),
            ):
                value = preflight_module.preflight(
                    home=home,
                    version_probe=lambda _path: preflight_module.ProbeResult(
                        0,
                        b"2.1.216 (Claude Code)\n",
                        b"",
                    ),
                    capability_probe=mutate_source,
                )

            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "executable-identity-drift")

    def test_unsafe_snapshot_metadata_is_inconclusive_not_version_mismatch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            installed = self._write_active_candidate(home)
            payload = installed.read_bytes()
            resolved = installed.resolve(strict=True)
            verified = claude_provenance.VerifiedClaudeExecutable(
                executable=resolved,
                artifact=claude_provenance.ClaudeReleaseArtifact(
                    version="2.1.212",
                    platform_key="darwin-arm64",
                    binary="claude",
                    checksum=hashlib.sha256(payload).hexdigest(),
                    size=len(payload),
                ),
                manifest_url="https://downloads.claude.ai/manifest.json",
                signature_url="https://downloads.claude.ai/manifest.json.sig",
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
            exact = self._write_active_candidate(home)
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
                return claude_provenance.VerifiedClaudeExecutable(
                    executable=resolved,
                    artifact=claude_provenance.ClaudeReleaseArtifact(
                        version=version,
                        platform_key=platform_key,
                        binary="claude",
                        checksum=hashlib.sha256(original_payload).hexdigest(),
                        size=len(original_payload),
                    ),
                    manifest_url="https://downloads.claude.ai/manifest.json",
                    signature_url="https://downloads.claude.ai/manifest.json.sig",
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
            exact = self._write_active_candidate(home)
            original_identity = preflight_module._identity
            verified_identity: dict[str, int] = {}

            def rewrite_after_binding(
                path: pathlib.Path,
                version: str,
                _version_probe: preflight_module.VersionProbe,
                _capability_probe: preflight_module.CapabilityProbe,
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
                return preflight_module.VerifiedCandidate(
                    resolved_path=path,
                    version=version,
                    platform_key="darwin-arm64",
                    checksum=hashlib.sha256(payload).hexdigest(),
                    artifact_size=len(payload),
                    identity=identity,
                    probe_result=preflight_module.ProbeResult(
                        0,
                        b"2.1.212 (Claude Code)\n",
                        b"",
                    ),
                    capabilities=claude_capabilities.validate_claude_capabilities(
                        f"{version} (Claude Code)\n",
                        _supported_help(),
                        expected_version=version,
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
            self._write_active_candidate(home)

            def replace_after_binding(
                path: pathlib.Path,
                version: str,
                _version_probe: preflight_module.VersionProbe,
                _capability_probe: preflight_module.CapabilityProbe,
            ) -> preflight_module.VerifiedCandidate:
                identity = preflight_module._identity(path)
                replacement = root / "different-claude"
                self._write_candidate(replacement)
                os.replace(replacement, path)
                return preflight_module.VerifiedCandidate(
                    resolved_path=path,
                    version=version,
                    platform_key="darwin-arm64",
                    checksum="a" * 64,
                    artifact_size=path.stat().st_size,
                    identity=identity,
                    probe_result=preflight_module.ProbeResult(
                        0,
                        b"2.1.216 (Claude Code)\n",
                        b"",
                    ),
                    capabilities=claude_capabilities.validate_claude_capabilities(
                        f"{version} (Claude Code)\n",
                        _supported_help(),
                        expected_version=version,
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
            self._write_active_candidate(home)
            probe_called = False

            def invalid_publisher_provenance(
                _path: pathlib.Path,
                _version: str,
                _version_probe: preflight_module.VersionProbe,
                _capability_probe: preflight_module.CapabilityProbe,
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
            self.assertNotEqual(value["reason"], "version-mismatch")

    def test_unexpected_verifier_error_is_bounded_inconclusive_without_probe(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            self._write_active_candidate(home)
            probe_called = False

            def broken_verifier(
                _path: pathlib.Path,
                _version: str,
                _version_probe: preflight_module.VersionProbe,
                _capability_probe: preflight_module.CapabilityProbe,
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
            self._write_active_candidate(home)
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
            self._write_active_candidate(home)
            probe_called = False

            def forbidden_probe(_path: pathlib.Path) -> preflight_module.ProbeResult:
                nonlocal probe_called
                probe_called = True
                raise AssertionError("probe must not run")

            with (
                mock.patch.object(preflight_module.sys, "platform", "darwin"),
                mock.patch.object(
                    pathlib.Path,
                    "open",
                    autospec=True,
                    side_effect=OSError("synthetic temporary read failure"),
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
                return claude_provenance.VerifiedClaudeExecutable(
                    executable=resolved,
                    artifact=artifact,
                    manifest_url="https://downloads.claude.ai/manifest.json",
                    signature_url="https://downloads.claude.ai/manifest.json.sig",
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
                    self._successful_capability_probe,
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
            self._write_active_candidate(home)
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
                "reason": "preflight-internal-error",
                "supported_version_range": EXPECTED_SUPPORTED_VERSION_RANGE,
            },
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
                    "reason": "invalid-arguments",
                    "supported_version_range": EXPECTED_SUPPORTED_VERSION_RANGE,
                },
            )


if __name__ == "__main__":
    unittest.main()
