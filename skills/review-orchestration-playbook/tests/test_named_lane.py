from __future__ import annotations

import ast
import contextlib
import hashlib
import io
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import py_compile
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import venv
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import named_lane as named_lane_runtime  # noqa: E402
from review_runtime.common import (  # noqa: E402
    ForwardedSignal,
    ReviewOutputDrainError,
    ReviewOutputLimitError,
    ReviewProcessLeakError,
    ReviewTimeoutError,
    TRUSTED_PATH,
)
from review_runtime.named_lane import (  # noqa: E402
    MATERIALIZER_BASE_REF,
    MATERIALIZER_HEAD_REF,
    SYMLINK_COUNT_LIMIT,
    NamedLaneGuardError,
    _read_symlink_blobs,
    _validate_materializer_git_version,
    _validate_materialized_gitlink,
    _validate_materialized_symlink,
    main as named_lane_main,
    materialize_worktree,
    run_claude as _run_claude,
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


def run_claude(**kwargs: object) -> dict[str, object]:
    if "preflight_result" not in kwargs:
        command = kwargs["command"]
        executable = pathlib.Path(command[0])
        kwargs["preflight_result"] = executable.with_name(
            f"{executable.name}.preflight.json"
        )
    return _run_claude(**kwargs)


class NamedLaneGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        temp_root = pathlib.Path(tempfile.gettempdir()).resolve()
        self.temporary = tempfile.TemporaryDirectory(
            prefix="named-lane-test-",
            dir=temp_root,
        )
        self.root = pathlib.Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-b", "master")
        git(self.repo, "config", "user.name", "Named Lane Test")
        git(self.repo, "config", "user.email", "named-lane@example.invalid")
        git(self.repo, "config", "commit.gpgsign", "false")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def commit(self, message: str = "fixture") -> str:
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-m", message)
        return git(self.repo, "rev-parse", "HEAD")

    def make_executable(self, source: str) -> pathlib.Path:
        executable = self.root / f"command-{time.monotonic_ns()}.py"
        executable.write_text(
            f"#!{sys.executable}\n{source}",
            encoding="utf-8",
        )
        executable.chmod(0o755)
        resolved = executable.resolve()
        self.write_preflight_result(resolved)
        return resolved

    def preflight_result_path(self, executable: pathlib.Path) -> pathlib.Path:
        return executable.with_name(f"{executable.name}.preflight.json")

    def write_preflight_result(self, executable: pathlib.Path) -> pathlib.Path:
        metadata = executable.lstat()
        version = "2.1.212"
        checksum = hashlib.sha256(executable.read_bytes()).hexdigest()
        evidence = {
            "capability_contract": {
                "required_options": [],
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
    ) -> tuple[str, ...]:
        if python_executable is None:
            python_executable = pathlib.Path(sys.executable).resolve()
        self.assertTrue(python_executable.is_absolute())
        self.assertTrue(python_executable.is_file())
        return (
            str(python_executable),
            "-I",
            "-B",
            "-S",
            str(guard),
            *arguments,
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

    def test_entrypoint_skips_global_sitecustomize_with_no_site(self) -> None:
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
        marker = self.root / "global-sitecustomize.marker"
        (site_packages / "sitecustomize.py").write_text(
            f"import pathlib\npathlib.Path({str(marker)!r}).write_text('loaded')\n",
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
            "PROFILE": str(
                scripts.parent / "references/claude-stream-schema.json"
            ),
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
        validated = validate_worktree(destination, head)
        self.assertEqual(validated.head_sha, head)
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
                multi_pack_index = command.index("core.multiPackIndex=false")
                self.assertEqual(command[multi_pack_index - 1], "-c")
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
        self.assertEqual(validate_worktree(destination, head).head_sha, head)

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
        self.assertEqual(validate_worktree(destination, head).head_sha, head)
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
        self.assertEqual(validate_worktree(destination, head).head_sha, head)

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
            validate_worktree(destination, head)
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
            multi_pack_index = command.index("core.multiPackIndex=false")
            self.assertEqual(command[multi_pack_index - 1], "-c")
        first_status_index = next(
            index
            for index, command in enumerate(validator_commands)
            if status_commands.intersection(command)
        )
        self.assertIn("status", validator_commands[first_status_index])

    def test_validator_fences_a_nonrepository_from_its_ancestor(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit("ancestor")
        nested = self.repo / "not-a-worktree"
        nested.mkdir(mode=0o700)
        original_capture = named_lane_runtime.run_bounded_capture
        observed_returncode: int | None = None
        observed_environment: dict[str, str] | None = None

        def observe_probe(argv: object, **kwargs: object) -> object:
            nonlocal observed_returncode, observed_environment
            command = tuple(argv)
            result = original_capture(command, **kwargs)
            if "--show-toplevel" in command:
                observed_returncode = result.returncode
                observed_environment = dict(kwargs["env"])
            return result

        with mock.patch.object(
            named_lane_runtime,
            "run_bounded_capture",
            side_effect=observe_probe,
        ):
            with self.assertRaisesRegex(
                NamedLaneGuardError,
                "bounded local Git preflight failed",
            ):
                validate_worktree(nested.resolve(), head)

        self.assertIsNotNone(observed_returncode)
        self.assertNotEqual(observed_returncode, 0)
        assert observed_environment is not None
        self.assertEqual(
            observed_environment["GIT_CEILING_DIRECTORIES"],
            str(nested.resolve().parent),
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
        self.assertEqual(validate_worktree(destination, head).head_sha, head)

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
        self.assertEqual(validate_worktree(destination, head).head_sha, head)

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
        self.assertEqual(validate_worktree(destination, head).head_sha, head)
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
        self.assertEqual(validate_worktree(destination, head).head_sha, head)

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
        first_admin = pathlib.Path(
            git(first_source, "rev-parse", "--absolute-git-dir")
        )
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
        self.assertEqual(validate_worktree(destination, head).head_sha, head)

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
            ("credential", "credential.helper", str(probe), "credential helpers"),
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
            ("shallow", "shallow repository state"),
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
                        elif label == "shallow":
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
        self.assertEqual(validate_worktree(destination, head).head_sha, head)

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
            returncode = named_lane_main(
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
            returncode = named_lane_main(
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
            returncode = named_lane_main(
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
            returncode = named_lane_main(
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
            returncode = named_lane_main(
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
            },
        )
        self.assertEqual(validate_worktree(destination, head).head_sha, head)

    def test_materializer_cli_receipt_commits_signal_while_unblocking(self) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        destination = self.root / "receipt-unblock-signal-lane"
        original_restore = named_lane_runtime.restore_signal_mask
        restore_calls = 0

        def interrupt_receipt_unblock(previous: object) -> None:
            nonlocal restore_calls
            restore_calls += 1
            if restore_calls == 3:
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
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = named_lane_main(
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

        self.assertGreaterEqual(restore_calls, 3)
        self.assertEqual(returncode, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(json.loads(stdout.getvalue())["status"], "ok")
        self.assertEqual(validate_worktree(destination, head).head_sha, head)

    def test_materializer_cli_receipt_commits_signal_during_outer_teardown(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
        base = self.commit("base")
        (self.repo / "tracked.txt").write_text("head\n", encoding="utf-8")
        head = self.commit("head")
        destination = self.root / "receipt-teardown-signal-lane"
        original_block = named_lane_runtime.block_forwarded_signals
        block_calls = 0

        def interrupt_outer_teardown() -> object:
            nonlocal block_calls
            block_calls += 1
            mask = original_block()
            if block_calls == 4:
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
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = named_lane_main(
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
        self.assertEqual(returncode, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(json.loads(stdout.getvalue())["status"], "ok")
        self.assertEqual(validate_worktree(destination, head).head_sha, head)

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
            returncode = named_lane_main(
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

        result = validate_worktree(self.repo.resolve(), head)

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

        result = validate_worktree((ancestor / self.repo.name).absolute(), head)

        self.assertEqual(result.root, self.repo.resolve())

    def test_worktree_path_with_symlink_leaf_is_rejected(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        worktree_link = self.root / "worktree-link"
        worktree_link.symlink_to(self.repo, target_is_directory=True)

        with self.assertRaisesRegex(NamedLaneGuardError, "real directory"):
            validate_worktree(worktree_link.absolute(), head)

    def test_absolute_and_relative_escaping_symlinks_are_rejected(self) -> None:
        for target in (str(self.root / "outside"), "../outside"):
            with self.subTest(target=target):
                link = self.repo / "escape"
                link.unlink(missing_ok=True)
                link.symlink_to(target)
                head = self.commit(f"escape {target}")
                with self.assertRaisesRegex(NamedLaneGuardError, "escapes"):
                    validate_worktree(self.repo.resolve(), head)

    def test_ignored_transitive_link_is_rejected_at_pristine_gate(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        (self.repo / ".gitignore").write_text("bridge\n", encoding="utf-8")
        (self.repo / "review-link").symlink_to("bridge")
        head = self.commit()
        (self.repo / "bridge").symlink_to(self.root / "outside")
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

        with self.assertRaisesRegex(NamedLaneGuardError, "must be clean"):
            validate_worktree(self.repo.resolve(), head)

    def test_guidance_symlink_is_rejected_even_when_it_stays_inside(self) -> None:
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "rules.md").write_text("rules\n", encoding="utf-8")
        (self.repo / "AGENTS.md").symlink_to("docs/rules.md")
        head = self.commit()

        with self.assertRaisesRegex(NamedLaneGuardError, "guidance must"):
            validate_worktree(self.repo.resolve(), head)

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
            validate_worktree(self.repo.resolve(), head)

    def test_skip_worktree_index_bit_is_rejected(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        git(self.repo, "update-index", "--skip-worktree", "AGENTS.md")

        with self.assertRaisesRegex(NamedLaneGuardError, "skip-worktree"):
            validate_worktree(self.repo.resolve(), head)

    def test_ignored_artifact_is_rejected_even_when_default_status_is_clean(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        (self.repo / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
        head = self.commit()
        (self.repo / "ignored.txt").write_text("artifact\n", encoding="utf-8")
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

        with self.assertRaisesRegex(NamedLaneGuardError, "must be clean"):
            validate_worktree(self.repo.resolve(), head)

    def test_gitlink_may_be_absent_or_an_empty_real_directory(self) -> None:
        head = self.add_deinitialized_gitlink()
        self.assertEqual(list((self.repo / "vendor").iterdir()), [])
        (self.repo / "vendor").chmod(0o700)
        os.utime(self.repo / "vendor", None)
        empty = validate_worktree(self.repo.resolve(), head)
        self.assertEqual(empty.head_sha, head)

        (self.repo / "vendor").rmdir()
        missing = validate_worktree(self.repo.resolve(), head)
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
            validate_worktree(self.repo.resolve(), head)

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
                validate_worktree(self.repo.resolve(), head)
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
        clean = validate_worktree(self.repo.resolve(), head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "submodule", "init", "--", "vendor")
        self.assertEqual(list((self.repo / "vendor").iterdir()), [])
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            validate_worktree(self.repo.resolve(), head)

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
        clean = validate_worktree(self.repo.resolve(), head)
        self.assertEqual(clean.head_sha, head)

        for suffix, value in (
            ("url", str(self.root / "submodule-source")),
            ("active", "true"),
        ):
            key = f"submodule.vendor.{suffix}"
            with self.subTest(key=key):
                git(self.repo, "config", "--worktree", key, value)
                with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
                    validate_worktree(self.repo.resolve(), head)
                git(self.repo, "config", "--worktree", "--unset-all", key)

    def test_global_submodule_active_uses_git_pathspec_precedence(self) -> None:
        head = self.add_deinitialized_gitlink()

        git(self.repo, "config", "submodule.unrelated.active", "not-a-boolean")
        git(self.repo, "config", "submodule.active", "unrelated")
        clean = validate_worktree(self.repo.resolve(), head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "config", "--replace-all", "submodule.active", "true")
        clean = validate_worktree(self.repo.resolve(), head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "config", "--replace-all", "submodule.active", "vendor")
        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            validate_worktree(self.repo.resolve(), head)

        git(self.repo, "config", "--replace-all", "submodule.active", "*")
        git(self.repo, "config", "--add", "submodule.active", ":(exclude)vendor")
        clean = validate_worktree(self.repo.resolve(), head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "config", "--replace-all", "submodule.active", "vendor")
        git(self.repo, "config", "submodule.vendor.active", "false")
        clean = validate_worktree(self.repo.resolve(), head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "config", "submodule.vendor.active", "true")
        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            validate_worktree(self.repo.resolve(), head)

    def test_global_submodule_active_reads_worktree_and_blocks_included_config(
        self,
    ) -> None:
        head = self.add_deinitialized_gitlink()
        git(self.repo, "config", "extensions.worktreeConfig", "true")
        git(self.repo, "config", "--worktree", "submodule.active", "vendor")
        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            validate_worktree(self.repo.resolve(), head)
        git(
            self.repo,
            "config",
            "--worktree",
            "--unset-all",
            "submodule.active",
        )

        included = self.root / "included-submodule-active.config"
        included.write_text("[submodule]\n\tactive = vendor\n", encoding="utf-8")
        git(self.repo, "config", "include.path", str(included))
        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "Git config include directives are not allowed",
        ):
            validate_worktree(self.repo.resolve(), head)

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
        clean = validate_worktree(self.repo.resolve(), head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "config", "submodule.named.path", "vendor")
        clean = validate_worktree(self.repo.resolve(), head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "config", "submodule.active", "vendor")
        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            validate_worktree(self.repo.resolve(), head)

        git(self.repo, "config", "submodule.named.active", "false")
        clean = validate_worktree(self.repo.resolve(), head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "config", "submodule.named.active", "true")
        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            validate_worktree(self.repo.resolve(), head)

        git(self.repo, "config", "--unset-all", "submodule.active")
        git(self.repo, "config", "--unset-all", "submodule.named.active")
        git(
            self.repo,
            "config",
            "submodule.named.url",
            str(self.root / "submodule-source"),
        )
        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            validate_worktree(self.repo.resolve(), head)

        git(self.repo, "config", "--unset-all", "submodule.named.path")
        git(self.repo, "config", "--unset-all", "submodule.named.url")
        git(self.repo, "config", "submodule.vendor.active", "true")
        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            validate_worktree(self.repo.resolve(), head)

    def test_raw_gitlink_reads_worktree_submodule_path_config(self) -> None:
        head = self.add_gitlink()
        git(self.repo, "config", "extensions.worktreeConfig", "true")
        git(self.repo, "config", "--worktree", "submodule.named.path", "vendor")
        git(self.repo, "config", "--worktree", "submodule.named.active", "true")

        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            validate_worktree(self.repo.resolve(), head)

    def test_raw_gitlink_without_mapping_honors_global_submodule_active(
        self,
    ) -> None:
        head = self.add_gitlink()

        git(self.repo, "config", "submodule.active", "vendor")
        with self.assertRaisesRegex(NamedLaneGuardError, "initialized"):
            validate_worktree(self.repo.resolve(), head)

        git(self.repo, "config", "--replace-all", "submodule.active", "unrelated")
        clean = validate_worktree(self.repo.resolve(), head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "config", "--replace-all", "submodule.active", "*")
        git(self.repo, "config", "--add", "submodule.active", ":(exclude)vendor")
        clean = validate_worktree(self.repo.resolve(), head)
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
            validate_worktree(self.repo.resolve(), head)

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

        result = validate_worktree(self.repo.resolve(), head)

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

        with self.assertRaisesRegex(
            NamedLaneGuardError, "bounded local Git preflight failed"
        ):
            validate_worktree(self.repo.resolve(), head)

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

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            returncode = named_lane_main(
                (
                    "validate-worktree",
                    "--worktree",
                    str(self.repo.resolve()),
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
            validate_worktree(self.repo.resolve(), head)

    def test_guard_does_not_scan_ordinary_file_contents(self) -> None:
        (self.repo / "AGENTS.md").write_text(
            "synthetic-looking text sk-" + "A" * 48 + "\n",
            encoding="utf-8",
        )
        head = self.commit()

        result = validate_worktree(self.repo.resolve(), head)

        self.assertEqual(result.symlink_count, 0)

    def test_exact_head_and_clean_status_are_required(self) -> None:
        tracked = self.repo / "AGENTS.md"
        tracked.write_text("one\n", encoding="utf-8")
        first = self.commit("first")
        tracked.write_text("two\n", encoding="utf-8")
        second = self.commit("second")

        with self.assertRaisesRegex(NamedLaneGuardError, "does not match"):
            validate_worktree(self.repo.resolve(), first)

        tracked.write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(NamedLaneGuardError, "must be clean"):
            validate_worktree(self.repo.resolve(), second)

        tracked.write_text("two\n", encoding="utf-8")
        untracked = self.repo / "untracked.txt"
        untracked.write_text("artifact\n", encoding="utf-8")
        with self.assertRaisesRegex(NamedLaneGuardError, "must be clean"):
            validate_worktree(self.repo.resolve(), second)

        with self.assertRaisesRegex(NamedLaneGuardError, "full Git object ID"):
            validate_worktree(self.repo.resolve(), "--not-a-revision")

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
            validate_worktree(self.repo.resolve(), head)

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
        clean = validate_worktree(self.repo.resolve(), head)
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
                    validate_worktree(self.repo.resolve(), head)
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
            validate_worktree(self.repo.resolve(), head)
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
        clean = validate_worktree(self.repo.resolve(), head)
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
                    validate_worktree(self.repo.resolve(), head)
                self.assertFalse(marker.exists())
                git(self.repo, "config", "--unset-all", key)

    def test_git_alias_is_blocked_before_reviewer_launch(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        marker = self.root / "alias-reviewer-started.marker"
        probe = self.make_executable(
            f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
        )
        git(self.repo, "config", "extensions.worktreeConfig", "true")

        for scope in ((), ("--worktree",)):
            with self.subTest(scope=scope or ("--local",)):
                git(self.repo, "config", *scope, "alias.foo", f"!{probe}")
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    returncode = named_lane_main(
                        (
                            "validate-worktree",
                            "--worktree",
                            str(self.repo.resolve()),
                            "--head",
                            head,
                        )
                    )

                self.assertEqual(returncode, 2)
                self.assertEqual(
                    json.loads(stderr.getvalue()),
                    {
                        "status": "blocked-safety",
                        "reason": (
                            "Git config aliases are not allowed before reviewer launch"
                        ),
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
            validate_worktree(self.repo.resolve(), head)

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
            "executable Git filter or diff commands",
        ):
            validate_worktree(self.repo.resolve(), head)

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
                clean = validate_worktree(self.repo.resolve(), head)
                self.assertEqual(clean.head_sha, head)

        for active in ("true", str(probe)):
            with self.subTest(active=active):
                git(self.repo, "config", "core.fsmonitor", active)
                with self.assertRaisesRegex(
                    NamedLaneGuardError,
                    "core.fsmonitor|bounded local Git preflight failed",
                ):
                    validate_worktree(self.repo.resolve(), head)
                self.assertFalse(marker.exists())

        git(self.repo, "config", "--unset-all", "core.fsmonitor")
        config_path = self.repo / ".git" / "config"
        with config_path.open("a", encoding="utf-8") as config:
            config.write("\n[core]\n\tfsmonitor\n")
        with self.assertRaisesRegex(NamedLaneGuardError, "core.fsmonitor"):
            validate_worktree(self.repo.resolve(), head)

    def test_core_fsmonitor_uses_local_and_worktree_precedence(
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
            validate_worktree(self.repo.resolve(), head)
        self.assertFalse(marker.exists())

        git(self.repo, "config", "extensions.worktreeConfig", "true")
        git(self.repo, "config", "--worktree", "core.fsmonitor", "false")
        clean = validate_worktree(self.repo.resolve(), head)
        self.assertEqual(clean.head_sha, head)

        git(self.repo, "config", "--worktree", "core.fsmonitor", "true")
        with self.assertRaisesRegex(NamedLaneGuardError, "core.fsmonitor"):
            validate_worktree(self.repo.resolve(), head)

        git(self.repo, "config", "--worktree", "core.fsmonitor", str(probe))
        with self.assertRaisesRegex(NamedLaneGuardError, "core.fsmonitor"):
            validate_worktree(self.repo.resolve(), head)
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
            validate_worktree(self.repo.resolve(), head)
        self.assertFalse(marker.exists())

    def test_malformed_external_include_fails_closed_during_identity_probe(
        self,
    ) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        included = self.root / "malformed-external.config"
        included.write_text("[broken\n", encoding="utf-8")
        git(self.repo, "config", "include.path", str(included))

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "bounded local Git preflight failed",
        ):
            validate_worktree(self.repo.resolve(), head)

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
            validate_worktree(self.repo.resolve(), head)

    def test_per_worktree_include_is_blocked(self) -> None:
        (self.repo / "AGENTS.md").write_text("guidance\n", encoding="utf-8")
        head = self.commit()
        included = self.root / "worktree-include.config"
        included.write_text("[core]\n\tfsmonitor = false\n", encoding="utf-8")
        git(self.repo, "config", "extensions.worktreeConfig", "true")
        git(self.repo, "config", "--worktree", "include.path", str(included))

        with self.assertRaisesRegex(
            NamedLaneGuardError,
            "Git config include directives are not allowed",
        ):
            validate_worktree(self.repo.resolve(), head)

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
            result = validate_worktree(self.repo.resolve(), head)

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

        result = run_claude(
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
            run_claude(
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
            run_claude(
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
            result = run_claude(
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
            result = run_claude(
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
            run_claude(
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
            run_claude(
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
                        run_claude(
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
                run_claude(
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
            run_claude(
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
                run_claude(
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
            run_claude(
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
            run_claude(
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
            run_claude(
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
                run_claude(
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
                run_claude(
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
            result = run_claude(
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
                    run_claude(
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
                run_claude(
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
                run_claude(
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
            "CLAUDE_CODE_OAUTH_TOKEN": "secret",
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
            run_claude(
                worktree=self.repo.resolve(),
                stdout_path=default_stdout,
                stderr_path=default_stderr,
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=2.0,
                stream_limit_bytes=16 * 1024,
            )
            run_claude(
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
        for key in denied.keys() - {"NODE_EXTRA_CA_CERTS"}:
            self.assertNotIn(key, child)
        self.assertNotIn("NODE_EXTRA_CA_CERTS", default_child)
        self.assertEqual(child["NODE_EXTRA_CA_CERTS"], str(node_extra_ca))
        self.assertEqual(child["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(child["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(child["GIT_NO_REPLACE_OBJECTS"], "1")
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
                        run_claude(
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
                    result = run_claude(
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
                        run_claude(
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
            run_claude(
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
            "import os, pathlib, sys, time\n"
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
            "pid_path = pathlib.Path(sys.argv[1])\n"
            "temporary_path = pid_path.with_suffix('.tmp')\n"
            "temporary_path.write_text(str(pid), encoding='ascii')\n"
            "os.replace(temporary_path, pid_path)\n"
            "os.write(ready_write, b'1')\n"
            "os.close(ready_write)\n"
            "os._exit(0)\n"
        )
        detached_pid: int | None = None
        try:
            result = run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.root / "detached.out",
                stderr_path=self.root / "detached.err",
                command=(str(executable), str(pid_path)),
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
            run_claude(
                worktree=self.repo.resolve(),
                stdout_path=self.repo / "stdout",
                stderr_path=self.root / "stderr",
                command=(str(executable),),
                prompt=b"",
                timeout_seconds=1.0,
                stream_limit_bytes=64,
            )
        with self.assertRaisesRegex(NamedLaneGuardError, "must be absolute"):
            run_claude(
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
            run_claude(
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
            run_claude(
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
            run_claude(
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
            run_claude(
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
            "import os, pathlib, sys\nos.chmod(pathlib.Path(sys.argv[1]), 0o755)\n"
        )

        try:
            with self.assertRaisesRegex(
                NamedLaneGuardError,
                "changed after validation",
            ):
                run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=output_parent / "stdout",
                    stderr_path=output_parent / "stderr",
                    command=(str(executable), str(output_parent)),
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
            "parent = pathlib.Path(sys.argv[1])\n"
            "displaced = pathlib.Path(sys.argv[2])\n"
            "redirect = pathlib.Path(sys.argv[3])\n"
            "os.rename(parent, displaced)\n"
            "os.symlink(redirect, parent, target_is_directory=True)\n"
            "sys.stdout.write('captured stdout')\n"
            "sys.stderr.write('captured stderr')\n"
        )

        with self.assertRaisesRegex(NamedLaneGuardError, "changed after validation"):
            run_claude(
                worktree=self.repo.resolve(),
                stdout_path=output_parent / "stdout.bin",
                stderr_path=output_parent / "stderr.bin",
                command=(
                    str(executable),
                    str(output_parent),
                    str(displaced_parent),
                    str(self.repo),
                ),
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
            "import os, pathlib, sys\n"
            "parent = pathlib.Path(sys.argv[1])\n"
            "displaced = pathlib.Path(sys.argv[2])\n"
            "redirect = pathlib.Path(sys.argv[3])\n"
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
                run_claude(
                    worktree=self.repo.resolve(),
                    stdout_path=output_parent / "stdout.bin",
                    stderr_path=output_parent / "stderr.bin",
                    command=(
                        str(executable),
                        str(output_parent),
                        str(displaced_parent),
                        str(self.repo),
                    ),
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
                run_claude(
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
                run_claude(
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
                    run_claude(
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
                run_claude(
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
                run_claude(
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
                run_claude(
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
                run_claude(
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
                run_claude(
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
                run_claude(
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
                    returncode = named_lane_main(argv)

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
            returncode = named_lane_main(
                (
                    "run-claude",
                    "--worktree",
                    str(self.repo.resolve()),
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
                    returncode = named_lane_main(
                        (
                            "run-claude",
                            "--worktree",
                            str(self.repo.resolve()),
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
                run_claude(
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
            returncode = named_lane_main(
                (
                    "run-claude",
                    "--worktree",
                    str(self.repo.resolve()),
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
                run_claude(
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
                    returncode = named_lane_main(argv)

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
                        run_claude(
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
            returncode = named_lane_main(argv)

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
            returncode = named_lane_main(argv)

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
                    "--head",
                    "0" * 40,
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
                        returncode = named_lane_main(argv)

                    self.assertEqual(returncode, expected_returncode)
                    self.assertEqual(
                        json.loads(stderr.getvalue()),
                        {"status": expected_status, "reason": reason},
                    )

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
                    "--head",
                    head,
                ),
                "blocked-safety",
            ),
            (
                (
                    "run-claude",
                    "--worktree",
                    str(self.repo.resolve()),
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
                    returncode = named_lane_main(argv)

                self.assertEqual(returncode, 2)
                self.assertEqual(
                    json.loads(stderr.getvalue()),
                    {"status": expected_status, "reason": "output-drain"},
                )


if __name__ == "__main__":
    unittest.main()
