from __future__ import annotations

import json
import hashlib
import errno
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

from review_runtime import claude_linux, claude_provenance  # noqa: E402
from review_runtime import named_claude_preflight as preflight_module  # noqa: E402


class NamedClaudePreflightTest(unittest.TestCase):
    def _write_candidate(
        self,
        path: pathlib.Path,
        *,
        marker: pathlib.Path | None = None,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = ["#!/bin/sh"]
        if marker is not None:
            lines.append(f"printf 'executed\\n' >> {marker}")
        lines.extend(("printf '2.1.212 (Claude Code)\\n'", "exit 0"))
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
    ) -> preflight_module.VerifiedCandidate:
        resolved = path.resolve(strict=True)
        return preflight_module.VerifiedCandidate(
            resolved_path=resolved,
            platform_key="darwin-arm64",
            checksum="a" * 64,
            artifact_size=resolved.stat().st_size,
            identity=preflight_module._identity(resolved),
            probe_result=probe_result
            or preflight_module.ProbeResult(
                0,
                b"2.1.212 (Claude Code)\n",
                b"",
            ),
        )

    def _verified_with_probe(
        self,
        path: pathlib.Path,
        version_probe: preflight_module.VersionProbe,
    ) -> preflight_module.VerifiedCandidate:
        return self._verified(path, version_probe(path))

    def test_only_active_2_1_216_is_blocked_without_executing_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            marker = root / "active-invocations"
            installed = home / ".local/share/claude/versions/2.1.216"
            self._write_candidate(installed, marker=marker)
            active = home / ".local/bin/claude"
            active.parent.mkdir(parents=True)
            active.symlink_to(installed)

            completed = self._run(home=home, path=str(root / "untrusted-bin"))
            value = json.loads(completed.stdout)

            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stderr, "")
            self.assertEqual(value["classification"], "blocked")
            self.assertEqual(value["reason"], "exact-version-mismatch")
            self.assertEqual(value["declared_version"], "2.1.216")
            self.assertEqual(value["source"], "active-installed")
            self.assertFalse(marker.exists())

    def test_declared_version_mismatch_loses_to_descriptor_identity_drift(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            marker = root / "active-invocations"
            installed = home / ".local/share/claude/versions/2.1.216"
            self._write_candidate(installed, marker=marker)
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
                    path.write_bytes(payload)
                    os.utime(
                        path,
                        ns=(before.st_atime_ns, before.st_mtime_ns),
                        follow_symlinks=False,
                    )
                    after = preflight_module._identity(path)
                    self.assertEqual(
                        tuple(after.values())[:-1],
                        tuple(identity.values())[:-1],
                    )
                    self.assertNotEqual(after["ctime_ns"], identity["ctime_ns"])
                return identity

            with mock.patch.object(
                preflight_module,
                "_stable_descriptor_identity",
                side_effect=rewrite_after_binding,
            ):
                value = preflight_module.preflight(home=home)

            self.assertEqual(value["classification"], "inconclusive")
            self.assertEqual(value["reason"], "executable-identity-drift")
            self.assertEqual(value["declared_version"], "2.1.216")
            self.assertFalse(marker.exists())

    def test_side_by_side_exact_is_verified_before_version_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            exact = home / ".local/share/claude/versions/2.1.212"
            self._write_candidate(exact)
            calls: list[tuple[str, pathlib.Path]] = []

            def verifier(
                path: pathlib.Path,
                version_probe: preflight_module.VersionProbe,
            ) -> preflight_module.VerifiedCandidate:
                calls.append(("verify", path))
                return self._verified(path, version_probe(path))

            def probe(path: pathlib.Path) -> preflight_module.ProbeResult:
                calls.append(("probe", path))
                return preflight_module.ProbeResult(
                    0,
                    b"2.1.212 (Claude Code)\n",
                    b"",
                )

            value = preflight_module.preflight(
                home=home,
                verifier=verifier,
                version_probe=probe,
            )

            self.assertEqual(value["classification"], "accepted")
            self.assertEqual(value["source"], "side-by-side-exact")
            self.assertEqual(value["resolved_path"], str(exact.resolve()))
            self.assertEqual([name for name, _path in calls], ["verify", "probe"])
            self.assertEqual(calls[0][1], exact.resolve())
            self.assertEqual(calls[1][1], exact.resolve())

    def test_wrong_explicit_override_does_not_fall_back_or_execute(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            explicit_marker = root / "explicit-invocations"
            side_marker = root / "side-invocations"
            explicit = root / "versions/2.1.216"
            exact = home / ".local/share/claude/versions/2.1.212"
            self._write_candidate(explicit, marker=explicit_marker)
            self._write_candidate(exact, marker=side_marker)

            completed = self._run(
                home=home,
                path="",
                args=("--claude-path", str(explicit)),
            )
            value = json.loads(completed.stdout)

            self.assertEqual(completed.returncode, 1)
            self.assertEqual(value["reason"], "exact-version-mismatch")
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
            self.assertEqual(value["reason"], "exact-version-unavailable")
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

            self.assertEqual(value["reason"], "exact-version-unavailable")
            self.assertFalse(marker.exists())

    def test_candidate_presence_io_failure_stops_before_lower_priority_fallback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            side_by_side = home / ".local/share/claude/versions/2.1.212"
            active = home / ".local/bin/claude"
            self._write_candidate(active)
            verifier_called = False
            original_lstat = pathlib.Path.lstat

            def fail_side_by_side_lstat(
                path: pathlib.Path,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                if path == side_by_side:
                    raise OSError(errno.EIO, "synthetic candidate inspection failure")
                return original_lstat(path, *args, **kwargs)  # type: ignore[arg-type]

            def forbidden_verifier(
                _path: pathlib.Path,
                _version_probe: preflight_module.VersionProbe,
            ) -> preflight_module.VerifiedCandidate:
                nonlocal verifier_called
                verifier_called = True
                raise AssertionError("lower-priority candidate must not be verified")

            with mock.patch.object(
                pathlib.Path,
                "lstat",
                autospec=True,
                side_effect=fail_side_by_side_lstat,
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
            side_by_side = home / ".local/share/claude/versions/2.1.212"
            active = home / ".local/bin/claude"
            self._write_candidate(side_by_side)
            self._write_candidate(active)
            original_exists = preflight_module._candidate_exists
            observed = False

            def observe_then_remove(path: pathlib.Path) -> bool:
                nonlocal observed
                if path == side_by_side and not observed:
                    observed = True
                    path.unlink()
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
            self.assertEqual(value["source"], "side-by-side-exact")

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

    def test_missing_exact_version_is_stable_blocked_json(self) -> None:
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
                    "reason": "exact-version-unavailable",
                    "required_version": "2.1.212",
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
            observed: dict[str, object] = {}

            def bounded_capture(*args, **kwargs):  # type: ignore[no-untyped-def]
                observed["args"] = args
                observed["kwargs"] = kwargs
                return types.SimpleNamespace(
                    returncode=0,
                    stdout=bytearray(b"2.1.212 (Claude Code)\n"),
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
            self.assertEqual(observed["args"], ((str(exact.resolve()), "--version"),))
            kwargs = observed["kwargs"]
            assert isinstance(kwargs, dict)
            self.assertEqual(kwargs["cwd"], pathlib.Path("/"))
            self.assertEqual(kwargs["env"], dict(preflight_module.VERSION_PROBE_ENV))
            self.assertIsNone(kwargs["stdin"])
            self.assertNotIn(str(repo), repr(observed))
            self.assertNotIn("ANTHROPIC_API_KEY", kwargs["env"])
            self.assertNotIn("CLAUDE_CODE_OAUTH_TOKEN", kwargs["env"])
            self.assertNotIn("GITHUB_TOKEN", kwargs["env"])

    def test_default_verifier_probes_private_snapshot_not_candidate_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            exact = home / ".local/share/claude/versions/2.1.212"
            self._write_candidate(exact)
            payload = exact.read_bytes()
            observed_probe_paths: list[pathlib.Path] = []

            def release_verifier(
                executable: pathlib.Path,
                *,
                version: str,
                platform_key: str,
                gpg_temp_root: pathlib.Path,
            ) -> claude_provenance.VerifiedClaudeExecutable:
                del gpg_temp_root
                resolved = executable.resolve(strict=True)
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

            def probe(path: pathlib.Path) -> preflight_module.ProbeResult:
                observed_probe_paths.append(path)
                self.assertNotEqual(path, exact.resolve())
                self.assertTrue(path.is_file())
                return preflight_module.ProbeResult(
                    0,
                    b"2.1.212 (Claude Code)\n",
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
                    side_effect=release_verifier,
                ),
            ):
                value = preflight_module.preflight(home=home, version_probe=probe)

            self.assertEqual(value["classification"], "accepted")
            self.assertEqual(len(observed_probe_paths), 1)
            self.assertFalse(observed_probe_paths[0].exists())

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

    def test_ctime_detects_in_place_rewrite_with_restored_size_and_mtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            exact = home / ".local/share/claude/versions/2.1.212"
            self._write_candidate(exact)

            def rewrite_after_binding(
                path: pathlib.Path,
                _version_probe: preflight_module.VersionProbe,
            ) -> preflight_module.VerifiedCandidate:
                before = path.stat(follow_symlinks=False)
                identity = preflight_module._identity(path)
                payload = path.read_bytes()
                replacement = bytes([payload[0] ^ 1]) + payload[1:]
                path.write_bytes(replacement)
                path.chmod(0o755)
                os.utime(
                    path,
                    ns=(before.st_atime_ns, before.st_mtime_ns),
                    follow_symlinks=False,
                )
                return preflight_module.VerifiedCandidate(
                    resolved_path=path,
                    platform_key="darwin-arm64",
                    checksum="a" * 64,
                    artifact_size=len(payload),
                    identity=identity,
                    probe_result=preflight_module.ProbeResult(
                        0,
                        b"2.1.212 (Claude Code)\n",
                        b"",
                    ),
                )

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
                _version_probe: preflight_module.VersionProbe,
            ) -> preflight_module.VerifiedCandidate:
                identity = preflight_module._identity(path)
                replacement = root / "different-claude"
                self._write_candidate(replacement)
                os.replace(replacement, path)
                return preflight_module.VerifiedCandidate(
                    resolved_path=path,
                    platform_key="darwin-arm64",
                    checksum="a" * 64,
                    artifact_size=path.stat().st_size,
                    identity=identity,
                    probe_result=preflight_module.ProbeResult(
                        0,
                        b"2.1.216 (Claude Code)\n",
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
                _version_probe: preflight_module.VersionProbe,
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
            self.assertNotEqual(value["reason"], "exact-version-mismatch")

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
                _version_probe: preflight_module.VersionProbe,
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
                    lambda _path: preflight_module.ProbeResult(
                        0,
                        b"2.1.212 (Claude Code)\n",
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
                "reason": "preflight-internal-error",
                "required_version": "2.1.212",
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
                    "required_version": "2.1.212",
                },
            )


if __name__ == "__main__":
    unittest.main()
