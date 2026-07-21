from __future__ import annotations

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
    ) -> preflight_module.VerifiedCandidate:
        resolved = path.resolve(strict=True)
        return preflight_module.VerifiedCandidate(
            resolved_path=resolved,
            platform_key="darwin-arm64",
            checksum="a" * 64,
            artifact_size=resolved.stat().st_size,
            identity=preflight_module._identity(resolved),
        )

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

    def test_side_by_side_exact_is_verified_before_version_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            home = root / "home"
            exact = home / ".local/share/claude/versions/2.1.212"
            self._write_candidate(exact)
            calls: list[tuple[str, pathlib.Path]] = []

            def verifier(path: pathlib.Path) -> preflight_module.VerifiedCandidate:
                calls.append(("verify", path))
                return self._verified(path)

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
                    verifier=self._verified,
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
