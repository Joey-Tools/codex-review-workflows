from __future__ import annotations

import contextlib
import io
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import py_compile
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
    SYMLINK_COUNT_LIMIT,
    NamedLaneGuardError,
    _read_symlink_blobs,
    _validate_materialized_gitlink,
    _validate_materialized_symlink,
    main as named_lane_main,
    run_claude,
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
        return executable.resolve()

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
            SCRIPTS.parent / "references/claude-2.1.212-stream-schema.json",
            references,
        )
        return scripts, guard

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
        cache_path = pathlib.Path(importlib.util.cache_from_source(str(source_path)))
        cache_path.parent.mkdir(exist_ok=True)
        py_compile.compile(
            str(malicious_source),
            cfile=str(cache_path),
            doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
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

        malicious_common = self.root / "malicious-common.py"
        malicious_common.write_text(
            "import pathlib\n"
            f"pathlib.Path({str(pyc_marker)!r}).write_text('loaded')\n"
            "raise RuntimeError('malicious common pyc executed')\n",
            encoding="utf-8",
        )
        common_cache = pathlib.Path(
            importlib.util.cache_from_source(str(runtime / "common.py"))
        )
        common_cache.parent.mkdir()
        py_compile.compile(
            str(malicious_common),
            cfile=str(common_cache),
            doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
        )

        expected_origins = {
            "review_runtime": str(runtime / "__init__.py"),
            "review_runtime.common": str(runtime / "common.py"),
            "review_runtime.named_lane": str(runtime / "named_lane.py"),
        }
        body = (
            "import json\n"
            f"expected = {expected_origins!r}\n"
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
            "review_runtime.claude_refresh_lock": str(
                runtime / "claude_refresh_lock.py"
            ),
            "review_runtime.claude_linux": str(runtime / "claude_linux.py"),
            "review_runtime.claude_provenance": str(runtime / "claude_provenance.py"),
            "review_runtime.named_claude_preflight": str(
                runtime / "named_claude_preflight.py"
            ),
        }
        expected_key = str(runtime / "claude_code_release.asc")
        body = (
            "import json\n"
            f"expected = {expected_origins!r}\n"
            f"expected_key = {expected_key!r}\n"
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
            "if namespace['_MAIN_ARGV'] != ('--sentinel',):\n"
            "    raise RuntimeError(f'arguments not forwarded: "
            "{namespace['_MAIN_ARGV']!r}')\n"
            "print(json.dumps(observed, sort_keys=True))\n"
        )
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

    def test_validator_entrypoint_loads_only_bound_manifest_source(self) -> None:
        scripts, guard = self.copy_guard_bundle()
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
        expected_schema = str(
            scripts.parent / "references/claude-2.1.212-stream-schema.json"
        )
        body = (
            "module = sys.modules['validate_claude_stream']\n"
            f"expected_origin = {expected_origin!r}\n"
            f"expected_schema = {expected_schema!r}\n"
            "if module.__file__ != expected_origin:\n"
            "    raise RuntimeError(f'unexpected validator file: {module.__file__}')\n"
            "if module.__spec__.origin != expected_origin:\n"
            "    raise RuntimeError(f'unexpected validator origin: "
            "{module.__spec__.origin}')\n"
            "if module.__package__ != '':\n"
            "    raise RuntimeError(f'unexpected validator package: "
            "{module.__package__!r}')\n"
            "if str(module.SCHEMA_PATH) != expected_schema:\n"
            "    raise RuntimeError(f'unexpected schema path: {module.SCHEMA_PATH}')\n"
            "if module.SCHEMA_BYTES != pathlib.Path(expected_schema).read_bytes():\n"
            "    raise RuntimeError('schema bytes were not bound exactly')\n"
            "loaded = sorted(name for name in sys.modules "
            "if name == 'validate_claude_stream' "
            "or name.startswith('validate_claude_stream.'))\n"
            "if loaded != ['validate_claude_stream']:\n"
            "    raise RuntimeError(f'unexpected validator closure: {loaded}')\n"
            "if namespace['_MAIN_ARGV'] != ('--sentinel',):\n"
            "    raise RuntimeError(f'arguments not forwarded: "
            "{namespace['_MAIN_ARGV']!r}')\n"
            "print(module.__spec__.origin)\n"
        )
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

    def test_control_companions_must_be_ordinary_non_symlink_files(self) -> None:
        cases = (
            (
                "preflight-claude",
                lambda scripts: scripts / "review_runtime/claude_code_release.asc",
            ),
            (
                "validate-claude-stream",
                lambda scripts: scripts.parent
                / "references/claude-2.1.212-stream-schema.json",
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
        scripts, guard = self.copy_guard_bundle()
        schema = scripts.parent / "references/claude-2.1.212-stream-schema.json"
        replacement = schema.with_name("replacement-schema.json")
        body = (
            "import os\n"
            f"schema = pathlib.Path({str(schema)!r})\n"
            f"replacement = pathlib.Path({str(replacement)!r})\n"
            "replacement.write_bytes(schema.read_bytes())\n"
            "os.replace(replacement, schema)\n"
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
        scripts, guard = self.copy_guard_bundle()
        schema = scripts.parent / "references/claude-2.1.212-stream-schema.json"
        body = (
            "import os\n"
            f"schema = pathlib.Path({str(schema)!r})\n"
            "before = os.stat(schema, follow_symlinks=False)\n"
            "with schema.open('r+b') as stream:\n"
            "    original = stream.read(1)\n"
            "    stream.seek(0)\n"
            "    stream.write(b'X' if original != b'X' else b'Y')\n"
            "    stream.flush()\n"
            "    os.fsync(stream.fileno())\n"
            "after = os.stat(schema, follow_symlinks=False)\n"
            "identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, "
            "value.st_uid, value.st_size)\n"
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

    def test_control_consumer_uses_bound_bytes_after_final_revalidation(self) -> None:
        scripts, guard = self.copy_guard_bundle()
        schema = scripts.parent / "references/claude-2.1.212-stream-schema.json"
        replacement = schema.with_name("post-validation-schema.json")
        body = (
            "import os\n"
            f"schema = pathlib.Path({str(schema)!r})\n"
            f"replacement = pathlib.Path({str(replacement)!r})\n"
            "module = sys.modules['validate_claude_stream']\n"
            "original_validate = namespace['_validate_bound_companion']\n"
            "initial_binding = original_validate(schema)\n"
            "replacement.write_bytes(b'not valid JSON')\n"
            "def validate_then_replace(path):\n"
            "    binding = original_validate(path)\n"
            "    os.replace(replacement, path)\n"
            "    return binding\n"
            "namespace['_validate_bound_companion'] = validate_then_replace\n"
            "def consume(_argv):\n"
            "    return module._load_contract()['claude_code_version']\n"
            "guarded = namespace['_guard_companions'](\n"
            "    consume, ((schema, initial_binding),)\n"
            ")\n"
            "version = guarded(())\n"
            "if version != '2.1.212':\n"
            "    raise RuntimeError(f'unexpected bound schema version: {version}')\n"
            "if schema.read_bytes() != b'not valid JSON':\n"
            "    raise RuntimeError('fixture did not replace the schema path')\n"
            "print(version)\n"
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
        self.assertEqual(completed.stdout.strip(), "2.1.212")

    def test_optional_control_load_failures_roll_back_their_namespaces(self) -> None:
        cases = (
            (
                "preflight-claude",
                "review_runtime",
                lambda scripts: scripts / "review_runtime/named_claude_preflight.py",
            ),
            (
                "validate-claude-stream",
                "validate_claude_stream",
                lambda scripts: scripts / "validate_claude_stream.py",
            ),
        )
        for subcommand, namespace_root, source_path in cases:
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
                        namespace_roots=(namespace_root,),
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
                "--api-key-source",
                "none",
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
        self.assertIn("stream.input-unreadable", result["reasons"])

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
                    timeout_seconds=2.0,
                    stream_limit_bytes=64,
                )

        self.assertTrue(failed_once)
        self.assertFalse(stdout.exists())
        self.assertFalse(stderr.exists())
        self.assertEqual(list(self.root.glob(".named-lane-*")), [])

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
        restore.assert_called_once_with(set())

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

        def interrupt_first_restore(mask: set[signal.Signals]) -> None:
            nonlocal restore_calls
            restore_calls += 1
            real_restore(mask)
            if restore_calls == 1:
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
                side_effect=interrupt_first_restore,
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
        self.assertEqual(restore_calls, 2)
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
                return_value=result,
            ) as run,
            mock.patch.object(named_lane_runtime, "_emit") as emit,
        ):
            returncode = named_lane_main(
                (
                    "run-claude",
                    "--worktree",
                    str(self.repo.resolve()),
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
        self.assertEqual(run.call_args.kwargs["timeout_seconds"], 3.5)
        self.assertEqual(run.call_args.kwargs["deadline_monotonic"], 105.0)

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
