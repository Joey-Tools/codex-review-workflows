from __future__ import annotations

import argparse
import importlib.machinery
import importlib.util
import hashlib
import io
import json
import os
import pathlib
import signal
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock


CANONICAL_SKILL_ROOT = (
    pathlib.Path(__file__).resolve().parents[2] / "review-orchestration-playbook"
)
SCRIPT_PATH = (
    CANONICAL_SKILL_ROOT / "scripts" / "isolated_external_review"
)
CANONICAL_WRAPPER_PATH = (
    CANONICAL_SKILL_ROOT / "scripts" / "isolated_review"
)
COMPAT_HELPER_PATH = (
    pathlib.Path(__file__).resolve().parents[1] / "scripts" / "isolated_external_review"
)
LEGACY_SCRIPT_PATH = (
    pathlib.Path(__file__).resolve().parents[1] / "scripts" / "isolated_copilot_review"
)
LEGACY_SKILL_SCRIPT_PATH = (
    pathlib.Path(__file__).resolve().parents[2]
    / "copilot-review-playbook"
    / "scripts"
    / "isolated_copilot_review"
)
SHIM_PATH = CANONICAL_SKILL_ROOT / "scripts" / "git_readonly_shim"


def run(
    cmd: list[str],
    *,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def git(repo: pathlib.Path, *args: str) -> subprocess.CompletedProcess[str]:
    return run(["git", "-C", str(repo), *args])


def git_commit(repo: pathlib.Path, message: str) -> None:
    completed = run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            message,
        ]
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr)


class IsolatedCopilotReviewTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="isolated-review-test-")
        self.root = pathlib.Path(self.tempdir.name)
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir()
        self.copilot_only_bin = self.root / "copilot-only-bin"
        self.copilot_only_bin.mkdir()
        self.gh_copilot_fallback_bin = self.root / "gh-copilot-fallback-bin"
        self.gh_copilot_fallback_bin.mkdir()
        self.output_file = self.root / "review.json"
        self.failure_file = self.root / "failure.json"
        self._write_fake_review_cli("agent")
        self._write_fake_review_cli("copilot")
        self._write_fake_review_cli("opencode")
        self._write_fake_codex_cli()
        self._write_fake_gh_cli()
        os.symlink(self.fake_bin / "copilot", self.copilot_only_bin / "copilot")
        os.symlink(self.fake_bin / "opencode", self.gh_copilot_fallback_bin / "opencode")
        os.symlink(self.fake_bin / "gh", self.gh_copilot_fallback_bin / "gh")
        self.repo = self._create_repo_with_submodule()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_real_git_prefers_homebrew_before_apple_git(self) -> None:
        module = self._load_script_module()
        seen_commands: list[list[str]] = []

        def fake_run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
            seen_commands.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, b"git version 2.0\n", b"")

        with mock.patch.object(
            module,
            "PREFERRED_GIT_PATHS",
            (
                "/opt/homebrew/bin/git",
                "/usr/local/bin/git",
                "/usr/bin/git",
            ),
        ), mock.patch.object(
            module.os.path,
            "isfile",
            return_value=True,
        ), mock.patch.object(
            module.os,
            "access",
            return_value=True,
        ), mock.patch.object(
            module.shutil,
            "which",
            return_value=None,
        ), mock.patch.object(
            module.subprocess,
            "run",
            side_effect=fake_run,
        ):
            self.assertTrue(
                module._resolve_real_git().startswith("/opt/homebrew/")
            )

        self.assertTrue(seen_commands[0][0].startswith("/opt/homebrew/"))
        self.assertEqual(seen_commands[0][1], "--version")

    def test_install_readonly_git_shim_replaces_existing_symlink(self) -> None:
        module = self._load_script_module()
        container = self.root / "shim-container"
        shim_dir = container / "tool-shims"
        shim_dir.mkdir(parents=True)
        installed_shim = shim_dir / "git"
        linked_target = self.root / "linked-target"
        linked_target.write_text("sentinel\n", encoding="utf-8")
        os.symlink(linked_target, installed_shim)

        module._install_readonly_git_shim(container)

        self.assertFalse(installed_shim.is_symlink())
        self.assertEqual(linked_target.read_text(encoding="utf-8"), "sentinel\n")
        first_line = installed_shim.read_text(encoding="utf-8").splitlines()[0]
        expected_shebang = f"#!{module._resolve_python_for_readonly_git_shim()}"
        self.assertEqual(first_line, expected_shebang)

    def _write_fake_review_cli(self, name: str) -> None:
        script = self.fake_bin / name
        script.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import json
                import os
                import pathlib
                import shutil
                import subprocess
                import sys

                args = sys.argv[1:]
                output = None
                fail = False
                agent_models_failure = os.environ.get("FAKE_AGENT_MODELS_FAIL", "")
                agent_models_fail_first = os.environ.get("FAKE_AGENT_MODELS_FAIL_FIRST", "")
                fail_agent_models_after_first = (
                    os.environ.get("FAKE_AGENT_MODELS_FAIL_AFTER_FIRST") == "1"
                )
                agent_models_counter_file = os.environ.get("FAKE_AGENT_MODELS_COUNTER_FILE")
                fail_opencode_models = os.environ.get("FAKE_OPENCODE_MODELS_FAIL") == "1"
                opencode_scope_bare_models = (
                    os.environ.get("FAKE_OPENCODE_SCOPE_BARE_MODELS") == "1"
                )
                hidden_agent_models = {
                    item
                    for item in os.environ.get("FAKE_AGENT_HIDE_MODELS", "").split(",")
                    if item
                }
                hidden_models = {
                    item
                    for item in os.environ.get("FAKE_OPENCODE_HIDE_MODELS", "").split(",")
                    if item
                }
                probe_git_status = False
                probe_git_diff = False
                probe_git_commit = False
                probe_git_config_diff = False
                probe_git_env_diff = False
                probe_git_exec_path = False
                if os.path.basename(sys.argv[0]) == "opencode" and args[:1] == ["models"]:
                    if fail_opencode_models:
                        print("simulated opencode models failure", file=sys.stderr)
                        raise SystemExit(3)
                    catalog = [
                        "github-copilot/claude-opus-4.7",
                        "github-copilot/claude-sonnet-4.6",
                        "openai/gpt-5.3-codex",
                    ]
                    scope = args[1] if len(args) > 1 else None
                    visible = [
                        model
                        for model in catalog
                        if model not in hidden_models
                        and (scope is None or model.startswith(f"{scope}/"))
                    ]
                    if scope is not None and opencode_scope_bare_models:
                        visible = [model.split("/", 1)[1] for model in visible]
                    print("\\n".join(visible))
                    raise SystemExit(0)
                if os.path.basename(sys.argv[0]) == "agent" and args[:1] == ["models"]:
                    if agent_models_fail_first:
                        if not agent_models_counter_file:
                            raise SystemExit("missing FAKE_AGENT_MODELS_COUNTER_FILE")
                        counter_path = pathlib.Path(agent_models_counter_file)
                        current_count = 0
                        if counter_path.exists():
                            current_count = int(counter_path.read_text(encoding="utf-8"))
                        counter_path.write_text(str(current_count + 1), encoding="utf-8")
                        if current_count == 0:
                            if agent_models_fail_first == "keychain":
                                print("SecItemCopyMatching failed -50", file=sys.stderr)
                            else:
                                print("simulated agent models failure", file=sys.stderr)
                            raise SystemExit(4)
                    if fail_agent_models_after_first:
                        if not agent_models_counter_file:
                            raise SystemExit("missing FAKE_AGENT_MODELS_COUNTER_FILE")
                        counter_path = pathlib.Path(agent_models_counter_file)
                        current_count = 0
                        if counter_path.exists():
                            current_count = int(counter_path.read_text(encoding="utf-8"))
                        counter_path.write_text(str(current_count + 1), encoding="utf-8")
                        if current_count >= 1:
                            print("SecItemCopyMatching failed -50", file=sys.stderr)
                            raise SystemExit(4)
                    if agent_models_failure:
                        if agent_models_failure == "keychain":
                            print("SecItemCopyMatching failed -50", file=sys.stderr)
                        else:
                            print("simulated agent models failure", file=sys.stderr)
                        raise SystemExit(4)
                    catalog = [
                        "claude-opus-4-7-thinking-high",
                        "claude-opus-4-7-high",
                        "gemini-3.1-pro",
                    ]
                    visible = [
                        model
                        for model in catalog
                        if model not in hidden_agent_models
                    ]
                    print("Available models")
                    print("")
                    for model in visible:
                        print(f"{model} - Fake model")
                    print("")
                    print("Tip: use --model <id> to switch.")
                    raise SystemExit(0)
                for index, arg in enumerate(args):
                    if arg == "--output":
                        output = pathlib.Path(args[index + 1])
                    if arg == "--fail":
                        fail = True
                    if arg == "--probe-git-status":
                        probe_git_status = True
                    if arg == "--probe-git-diff":
                        probe_git_diff = True
                    if arg == "--probe-git-commit":
                        probe_git_commit = True
                    if arg == "--probe-git-config-diff":
                        probe_git_config_diff = True
                    if arg == "--probe-git-env-diff":
                        probe_git_env_diff = True
                    if arg == "--probe-git-exec-path":
                        probe_git_exec_path = True
                if output is None and os.environ.get("FAKE_REVIEW_OUTPUT_FILE"):
                    output = pathlib.Path(os.environ["FAKE_REVIEW_OUTPUT_FILE"])
                if output is None:
                    raise SystemExit("missing --output")

                repo = pathlib.Path.cwd()
                sub_tracked_path = repo / "deps/sub/sub.txt"
                sub_untracked_path = repo / "deps/sub/scratch.txt"
                sub_git_toplevel = None
                if sub_tracked_path.exists():
                    completed = subprocess.run(
                        ["git", "-C", str(sub_tracked_path.parent), "rev-parse", "--show-toplevel"],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    if completed.returncode == 0:
                        sub_git_toplevel = completed.stdout.strip()
                payload = {
                    "tool": pathlib.Path(sys.argv[0]).name,
                    "entrypoint": os.environ.get("CODEX_ISOLATED_REVIEW_ENTRYPOINT"),
                    "prompt_delivery": os.environ.get("CODEX_ISOLATED_REVIEW_PROMPT_DELIVERY"),
                    "review_base": os.environ.get("CODEX_ISOLATED_REVIEW_BASE_REF"),
                    "review_head": os.environ.get("CODEX_ISOLATED_REVIEW_HEAD_REF"),
                    "review_range": os.environ.get("CODEX_ISOLATED_REVIEW_RANGE"),
                    "cwd": str(repo),
                    "args": args,
                    "root_tracked": (repo / "root.txt").read_text(encoding="utf-8"),
                    "root_untracked": (repo / "notes.txt").read_text(encoding="utf-8")
                    if (repo / "notes.txt").exists()
                    else None,
                    "sub_tracked": sub_tracked_path.read_text(encoding="utf-8") if sub_tracked_path.exists() else None,
                    "sub_untracked": sub_untracked_path.read_text(encoding="utf-8") if sub_untracked_path.exists() else None,
                    "sub_git_toplevel": sub_git_toplevel,
                    "prompt_file": os.environ.get("CODEX_ISOLATED_REVIEW_PROMPT_FILE"),
                    "diff_file": os.environ.get("CODEX_ISOLATED_REVIEW_DIFF_FILE"),
                    "prompt_text": os.environ.get("CODEX_ISOLATED_REVIEW_PROMPT_TEXT"),
                    "report_file": os.environ.get("CODEX_ISOLATED_REVIEW_REPORT_FILE"),
                    "final_reply": os.environ.get("CODEX_ISOLATED_REVIEW_FINAL_REPLY"),
                    "git_policy": os.environ.get("CODEX_ISOLATED_REVIEW_GIT_POLICY"),
                    "git_shim": os.environ.get("CODEX_ISOLATED_REVIEW_GIT_SHIM"),
                    "git_resolved": shutil.which("git"),
                    "opencode_config": os.environ.get("OPENCODE_CONFIG"),
                    "opencode_config_dir": os.environ.get("OPENCODE_CONFIG_DIR"),
                    "xdg_data_home": os.environ.get("XDG_DATA_HOME"),
                }
                if probe_git_status:
                    completed = subprocess.run(
                        ["git", "status", "--short"],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    payload["git_status"] = {
                        "returncode": completed.returncode,
                        "stdout": completed.stdout,
                        "stderr": completed.stderr,
                    }
                if probe_git_diff:
                    completed = subprocess.run(
                        ["git", "diff", "--stat", "HEAD"],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    payload["git_diff"] = {
                        "returncode": completed.returncode,
                        "stdout": completed.stdout,
                        "stderr": completed.stderr,
                    }
                if probe_git_commit:
                    completed = subprocess.run(
                        [
                            "git",
                            "commit",
                            "--allow-empty",
                            "-m",
                            "probe",
                        ],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    payload["git_commit"] = {
                        "returncode": completed.returncode,
                        "stdout": completed.stdout,
                        "stderr": completed.stderr,
                    }
                if probe_git_config_diff:
                    completed = subprocess.run(
                        [
                            "git",
                            "-c",
                            "diff.external=echo BYPASS",
                            "diff",
                            "HEAD",
                        ],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    payload["git_config_diff"] = {
                        "returncode": completed.returncode,
                        "stdout": completed.stdout,
                        "stderr": completed.stderr,
                    }
                if probe_git_env_diff:
                    diff_env = dict(os.environ)
                    diff_env["GIT_EXTERNAL_DIFF"] = "echo ENV_BYPASS"
                    completed = subprocess.run(
                        [
                            "git",
                            "diff",
                            "HEAD",
                        ],
                        text=True,
                        capture_output=True,
                        check=False,
                        env=diff_env,
                    )
                    payload["git_env_diff"] = {
                        "returncode": completed.returncode,
                        "stdout": completed.stdout,
                        "stderr": completed.stderr,
                    }
                if probe_git_exec_path:
                    completed = subprocess.run(
                        [
                            "git",
                            "--exec-path=/tmp/not-real-git",
                            "log",
                            "-1",
                        ],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    payload["git_exec_path"] = {
                        "returncode": completed.returncode,
                        "stdout": completed.stdout,
                        "stderr": completed.stderr,
                    }
                if payload["prompt_file"]:
                    payload["prompt_file_content"] = pathlib.Path(payload["prompt_file"]).read_text(
                        encoding="utf-8"
                    )
                if payload["diff_file"]:
                    payload["diff_file_content"] = pathlib.Path(payload["diff_file"]).read_text(
                        encoding="utf-8"
                    )
                if payload["opencode_config"]:
                    payload["opencode_config_content"] = pathlib.Path(
                        payload["opencode_config"]
                    ).read_text(encoding="utf-8")
                if payload["report_file"]:
                    report_path = pathlib.Path(payload["report_file"])
                    report_path.parent.mkdir(parents=True, exist_ok=True)
                    report_path.write_text(
                        "# Fake review report\\n\\nLGTM\\n",
                        encoding="utf-8",
                    )
                output.write_text(json.dumps(payload), encoding="utf-8")
                raise SystemExit(7 if fail else 0)
                """
            ),
            encoding="utf-8",
        )
        script.chmod(0o755)

    def _write_fake_gh_cli(self) -> None:
        script = self.fake_bin / "gh"
        script.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import json
                import os
                import pathlib
                import shutil
                import sys

                args = sys.argv[1:]
                if not args or args[0] != "copilot":
                    raise SystemExit("unsupported gh subcommand")
                args = args[1:]
                if args[:1] == ["--"]:
                    args = args[1:]

                output = None
                prompt = None
                index = 0
                while index < len(args):
                    arg = args[index]
                    if arg == "--output":
                        output = pathlib.Path(args[index + 1])
                        index += 2
                        continue
                    if arg in ("-p", "--prompt"):
                        prompt = args[index + 1]
                        index += 2
                        continue
                    if arg in ("-i", "--interactive"):
                        prompt = "<interactive>"
                        index += 1
                        continue
                    index += 1

                if output is None:
                    raise SystemExit("missing --output")
                if prompt is None:
                    print("Invalid command format", file=sys.stderr)
                    print("", file=sys.stderr)
                    print(
                        "For non-interactive mode, use the -p or --prompt option.",
                        file=sys.stderr,
                    )
                    print("Try 'copilot --help' for more information.", file=sys.stderr)
                    raise SystemExit(2)
                if (
                    os.environ.get("FAKE_GH_REQUIRES_COPILOT") == "1"
                    and shutil.which("copilot") is None
                ):
                    print("! Copilot CLI not installed", file=sys.stderr)
                    raise SystemExit(3)

                payload = {
                    "tool": "gh",
                    "entrypoint": os.environ.get("CODEX_ISOLATED_REVIEW_ENTRYPOINT"),
                    "args": args,
                    "prompt": prompt,
                }
                output.write_text(json.dumps(payload), encoding="utf-8")
                raise SystemExit(0)
                """
            ),
            encoding="utf-8",
        )
        script.chmod(0o755)

    def _write_fake_codex_cli(self) -> None:
        script = self.fake_bin / "codex"
        script.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import json
                import os
                import pathlib
                import shutil
                import subprocess
                import sys
                import time

                args = sys.argv[1:]
                if args == ["--version"]:
                    print("codex-cli fake")
                    raise SystemExit(0)
                if args[:2] == ["sandbox", "linux"]:
                    index = 2
                    while index < len(args) - 1:
                        arg = args[index]
                        if arg in ("--enable", "--disable"):
                            index += 2
                            continue
                        raise SystemExit(f"unsupported codex sandbox invocation: {args}")
                    completed = subprocess.run(
                        args[index:],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    if completed.stdout:
                        sys.stdout.write(completed.stdout)
                    if completed.stderr:
                        sys.stderr.write(completed.stderr)
                    raise SystemExit(completed.returncode)
                sandbox = None
                enabled_features = []
                disabled_features = []
                index = 0
                while index < len(args):
                    arg = args[index]
                    if arg == "--enable":
                        enabled_features.append(args[index + 1])
                        index += 2
                        continue
                    if arg == "--disable":
                        disabled_features.append(args[index + 1])
                        index += 2
                        continue
                    if arg == "-s":
                        sandbox = args[index + 1]
                        index += 2
                        continue
                    if arg == "--add-dir":
                        index += 2
                        continue
                    break

                if args[index:index + 1] != ["exec"]:
                    raise SystemExit(f"unsupported codex invocation: {args}")
                remaining_args = args[index + 1 :]
                exec_args = []
                review_args = remaining_args
                used_review_subcommand = False
                if "review" in remaining_args:
                    review_index = remaining_args.index("review")
                    exec_args = remaining_args[:review_index]
                    review_args = remaining_args[review_index + 1 :]
                    used_review_subcommand = True
                output = None
                probe_git_commit = os.environ.get("FAKE_CODEX_PROBE_GIT_COMMIT") == "1"
                pointer = 0
                while pointer < len(review_args):
                    arg = review_args[pointer]
                    if arg in ("-o", "--output-last-message"):
                        output = pathlib.Path(review_args[pointer + 1])
                        pointer += 2
                        continue
                    if arg == "--probe-git-commit":
                        probe_git_commit = True
                    pointer += 1

                prompt_stdin = None
                if "-" in review_args:
                    prompt_stdin = sys.stdin.read()

                isolated_entrypoint = os.environ.get("CODEX_ISOLATED_REVIEW_ENTRYPOINT")
                fail_entrypoints = {
                    item.strip()
                    for item in os.environ.get("FAKE_CODEX_FAIL_ENTRYPOINTS", "").split(",")
                    if item.strip()
                }
                if isolated_entrypoint in fail_entrypoints:
                    print(
                        f"simulated codex failure for {isolated_entrypoint}",
                        file=sys.stderr,
                    )
                    raise SystemExit(9)

                payload = {
                    "tool": "codex",
                    "argv0": str(pathlib.Path(sys.argv[0]).resolve()),
                    "path_env": os.environ.get("PATH"),
                    "sandbox": sandbox,
                    "cwd": str(pathlib.Path.cwd()),
                    "args": args,
                    "enabled_features": enabled_features,
                    "disabled_features": disabled_features,
                    "exec_args": exec_args,
                    "used_review_subcommand": used_review_subcommand,
                    "review_args": review_args,
                    "codex_ci": os.environ.get("CODEX_CI"),
                    "codex_home": os.environ.get("CODEX_HOME"),
                    "codex_internal_originator_override": os.environ.get(
                        "CODEX_INTERNAL_ORIGINATOR_OVERRIDE"
                    ),
                    "codex_sandbox_network_disabled": os.environ.get(
                        "CODEX_SANDBOX_NETWORK_DISABLED"
                    ),
                    "codex_shell": os.environ.get("CODEX_SHELL"),
                    "codex_thread_id": os.environ.get("CODEX_THREAD_ID"),
                    "review_base": os.environ.get("CODEX_ISOLATED_REVIEW_BASE_REF"),
                    "review_head": os.environ.get("CODEX_ISOLATED_REVIEW_HEAD_REF"),
                    "review_range": os.environ.get("CODEX_ISOLATED_REVIEW_RANGE"),
                    "prompt_stdin": prompt_stdin,
                    "inherited_secret_token": os.environ.get("INHERITED_SECRET_TOKEN"),
                    "openai_api_key": os.environ.get("OPENAI_API_KEY"),
                    "https_proxy": os.environ.get("HTTPS_PROXY"),
                    "requests_ca_bundle": os.environ.get("REQUESTS_CA_BUNDLE"),
                    "git_policy": os.environ.get("CODEX_ISOLATED_REVIEW_GIT_POLICY"),
                    "git_shim": os.environ.get("CODEX_ISOLATED_REVIEW_GIT_SHIM"),
                    "git_resolved": shutil.which("git"),
                    "prompt_file": os.environ.get("CODEX_ISOLATED_REVIEW_PROMPT_FILE"),
                    "diff_file": os.environ.get("CODEX_ISOLATED_REVIEW_DIFF_FILE"),
                    "final_file": os.environ.get("CODEX_ISOLATED_REVIEW_FINAL_FILE"),
                    "tmpdir": os.environ.get("TMPDIR"),
                    "tmp": os.environ.get("TMP"),
                    "temp": os.environ.get("TEMP"),
                    "tmpprefix": os.environ.get("TMPPREFIX"),
                }
                if os.environ.get("FAKE_CODEX_REQUIRE_SENTINEL") == "1":
                    if os.environ.get("FAKE_CODEX_SENTINEL") != "present":
                        raise SystemExit("missing inherited sentinel env")
                if probe_git_commit:
                    completed = subprocess.run(
                        [
                            "git",
                            "commit",
                            "--allow-empty",
                            "-m",
                            "probe",
                        ],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    payload["git_commit"] = {
                        "returncode": completed.returncode,
                        "stdout": completed.stdout,
                        "stderr": completed.stderr,
                    }

                delay = float(os.environ.get("FAKE_CODEX_REVIEW_DELAY_SECS", "0"))
                final_message = (
                    os.environ.get(
                        f"FAKE_CODEX_FINAL_MESSAGE_{isolated_entrypoint.upper().replace('-', '_')}"
                    )
                    if isolated_entrypoint
                    else None
                )
                if final_message is None:
                    final_message = os.environ.get("FAKE_CODEX_FINAL_MESSAGE", "No findings.\\n")
                if delay:
                    time.sleep(delay)

                print(json.dumps({"event": "payload", "payload": payload}))
                if output is not None:
                    output.write_text(final_message, encoding="utf-8")
                raise SystemExit(0)
                """
            ),
            encoding="utf-8",
        )
        script.chmod(0o755)

    def _create_repo_with_submodule(self) -> pathlib.Path:
        sub_remote = self.root / "submodule-remote"
        sub_remote.mkdir()
        self.assertEqual(git(sub_remote, "init").returncode, 0)
        (sub_remote / "sub.txt").write_text("sub-base\n", encoding="utf-8")
        self.assertEqual(git(sub_remote, "add", "sub.txt").returncode, 0)
        git_commit(sub_remote, "init submodule")

        repo = self.root / "repo"
        repo.mkdir()
        self.assertEqual(git(repo, "init").returncode, 0)
        self.assertEqual(git(repo, "config", "protocol.file.allow", "always").returncode, 0)
        (repo / "root.txt").write_text("root-base\n", encoding="utf-8")
        self.assertEqual(git(repo, "add", "root.txt").returncode, 0)
        git_commit(repo, "init repo")

        add_submodule = run(
            [
                "git",
                "-C",
                str(repo),
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                str(sub_remote),
                "deps/sub",
            ]
        )
        self.assertEqual(add_submodule.returncode, 0, add_submodule.stderr)
        self.assertEqual(git(repo, "add", ".gitmodules", "deps/sub").returncode, 0)
        git_commit(repo, "add submodule")

        (repo / "root.txt").write_text("root-dirty\n", encoding="utf-8")
        (repo / "notes.txt").write_text("root-untracked\n", encoding="utf-8")
        (repo / ".codex-tmp").mkdir()
        (repo / ".codex-tmp" / "review.diff").write_text(
            "diff --git a/root.txt b/root.txt\n",
            encoding="utf-8",
        )
        (repo / ".codex-tmp" / "review.prompt").write_text(
            "Review {workspace} with diff {diff_file}",
            encoding="utf-8",
        )

        submodule = repo / "deps/sub"
        (submodule / "sub.txt").write_text("sub-dirty\n", encoding="utf-8")
        (submodule / "scratch.txt").write_text("sub-untracked\n", encoding="utf-8")
        return repo

    def _create_plain_repo(self, name: str, *, initial_content: str = "base\n") -> pathlib.Path:
        repo = self.root / name
        repo.mkdir()
        self.assertEqual(git(repo, "init").returncode, 0)
        (repo / "file.txt").write_text(initial_content, encoding="utf-8")
        self.assertEqual(git(repo, "add", "file.txt").returncode, 0)
        git_commit(repo, f"init {name}")
        return repo

    def _create_review_range_repo(self, name: str) -> tuple[pathlib.Path, str, str]:
        repo = self.root / name
        repo.mkdir()
        self.assertEqual(git(repo, "init").returncode, 0)
        (repo / "root.txt").write_text("root-base\n", encoding="utf-8")
        self.assertEqual(git(repo, "add", "root.txt").returncode, 0)
        git_commit(repo, f"init {name}")
        base = git(repo, "rev-parse", "HEAD").stdout.strip()
        self.assertEqual(git(repo, "switch", "-c", "wip/range-review").returncode, 0)
        (repo / "root.txt").write_text("root-head\n", encoding="utf-8")
        self.assertEqual(git(repo, "add", "root.txt").returncode, 0)
        git_commit(repo, f"update {name}")
        head = git(repo, "rev-parse", "HEAD").stdout.strip()
        (repo / "root.txt").write_text("root-live-dirty\n", encoding="utf-8")
        (repo / ".codex-tmp").mkdir()
        (repo / ".codex-tmp" / "range.prompt").write_text(
            "Review {review_range} from {base_ref} to {head_ref} using {diff_file}",
            encoding="utf-8",
        )
        return repo, base, head

    def _create_divergent_review_range_repo(
        self,
        name: str,
    ) -> tuple[pathlib.Path, str, str, str]:
        repo = self.root / name
        repo.mkdir()
        self.assertEqual(git(repo, "init").returncode, 0)
        (repo / "root.txt").write_text("root-base\n", encoding="utf-8")
        self.assertEqual(git(repo, "add", "root.txt").returncode, 0)
        git_commit(repo, f"init {name}")
        common_base = git(repo, "rev-parse", "HEAD").stdout.strip()

        self.assertEqual(git(repo, "switch", "-c", "wip/range-review").returncode, 0)
        (repo / "root.txt").write_text("feature-head\n", encoding="utf-8")
        self.assertEqual(git(repo, "add", "root.txt").returncode, 0)
        git_commit(repo, f"feature {name}")
        head = git(repo, "rev-parse", "HEAD").stdout.strip()

        self.assertEqual(
            git(repo, "switch", "-c", "target-review", common_base).returncode,
            0,
        )
        (repo / "root.txt").write_text("target-head\n", encoding="utf-8")
        self.assertEqual(git(repo, "add", "root.txt").returncode, 0)
        git_commit(repo, f"target {name}")
        base = git(repo, "rev-parse", "HEAD").stdout.strip()
        return repo, base, head, common_base

    def _create_unrelated_review_range_repo(
        self,
        name: str,
    ) -> tuple[pathlib.Path, str, str]:
        repo = self.root / name
        repo.mkdir()
        self.assertEqual(git(repo, "init").returncode, 0)
        (repo / "root.txt").write_text("root-base\n", encoding="utf-8")
        self.assertEqual(git(repo, "add", "root.txt").returncode, 0)
        git_commit(repo, f"init {name}")
        base = git(repo, "rev-parse", "HEAD").stdout.strip()

        self.assertEqual(
            git(repo, "switch", "--orphan", "wip/unrelated-review").returncode,
            0,
        )
        if (repo / "root.txt").exists():
            (repo / "root.txt").unlink()
        (repo / "orphan.txt").write_text("orphan-head\n", encoding="utf-8")
        self.assertEqual(git(repo, "add", "orphan.txt").returncode, 0)
        git_commit(repo, f"orphan {name}")
        head = git(repo, "rev-parse", "HEAD").stdout.strip()
        return repo, base, head

    def _create_filter_repo(
        self,
        name: str,
        *,
        trigger: pathlib.Path,
        driver: str = "foo",
    ) -> pathlib.Path:
        repo = self.root / name
        repo.mkdir()
        self.assertEqual(git(repo, "init").returncode, 0)
        self.assertEqual(git(repo, "config", "user.name", "Test User").returncode, 0)
        self.assertEqual(git(repo, "config", "user.email", "test@example.com").returncode, 0)
        self.assertEqual(
            git(repo, "config", f"filter.{driver}.clean", f"touch {trigger}").returncode,
            0,
        )
        self.assertEqual(
            git(repo, "config", f"filter.{driver}.smudge", "cat").returncode,
            0,
        )
        (repo / ".gitattributes").write_text(f"* filter={driver}\n", encoding="utf-8")
        (repo / "file.txt").write_text("base\n", encoding="utf-8")
        self.assertEqual(git(repo, "add", ".gitattributes", "file.txt").returncode, 0)
        git_commit(repo, f"init {name}")
        (repo / "file.txt").write_text("changed\n", encoding="utf-8")
        return repo

    def _create_diff_driver_repo(self, name: str) -> pathlib.Path:
        repo = self._create_plain_repo(name)
        self.assertEqual(
            git(repo, "config", "diff.pwned.command", "echo EXTDIFF_TRIGGER").returncode,
            0,
        )
        self.assertEqual(
            git(repo, "config", "diff.pwned.textconv", "echo TEXTCONV_TRIGGER").returncode,
            0,
        )
        (repo / ".gitattributes").write_text("*.txt diff=pwned\n", encoding="utf-8")
        self.assertEqual(git(repo, "add", ".gitattributes").returncode, 0)
        git_commit(repo, f"enable diff driver for {name}")
        (repo / "file.txt").write_text("changed\n", encoding="utf-8")
        return repo

    def _create_hooks_path_repo(self, name: str, *, trigger: pathlib.Path) -> pathlib.Path:
        repo = self._create_plain_repo(name)
        hooks = self.root / f"{name}-hooks"
        hooks.mkdir()
        hook = hooks / "post-index-change"
        hook.write_text(
            f"#!/bin/sh\ntouch {trigger}\n",
            encoding="utf-8",
        )
        hook.chmod(0o755)
        self.assertEqual(
            git(repo, "config", "core.hooksPath", str(hooks)).returncode,
            0,
        )
        (repo / "file.txt").write_text("changed\n", encoding="utf-8")
        return repo

    def _create_fake_signed_repo(self, name: str) -> tuple[pathlib.Path, str]:
        repo = self._create_plain_repo(name)
        tree = git(repo, "write-tree").stdout.strip()
        author = "Test User <test@example.com> 0 +0000"
        commit_text = textwrap.dedent(
            f"""\
            tree {tree}
            author {author}
            committer {author}
            gpgsig -----BEGIN PGP SIGNATURE-----
             bogus
             -----END PGP SIGNATURE-----

            fake signed commit
            """
        )
        fake_commit = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "hash-object",
                "-t",
                "commit",
                "-w",
                "--stdin",
            ],
            input=commit_text,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(fake_commit.returncode, 0, fake_commit.stderr)
        ref_name = "fake-signed"
        self.assertEqual(
            git(repo, "update-ref", f"refs/heads/{ref_name}", fake_commit.stdout.strip()).returncode,
            0,
        )
        fake_gpg = repo / "fake-gpg"
        fake_gpg.write_text(
            "#!/bin/sh\necho GPG_TRIGGER >&2\nexit 1\n",
            encoding="utf-8",
        )
        fake_gpg.chmod(0o755)
        self.assertEqual(
            git(repo, "config", "gpg.program", str(fake_gpg)).returncode,
            0,
        )
        return repo, ref_name

    def _run_git_show_signature(
        self,
        repo: pathlib.Path,
        rev: str,
    ) -> subprocess.CompletedProcess[str]:
        return run(
            [
                "git",
                "-C",
                str(repo),
                "show",
                "--show-signature",
                "--no-patch",
                rev,
            ]
        )

    def _base_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["PATH"] = f"{self.fake_bin}:{env['PATH']}"
        env["ISOLATED_EXTERNAL_REVIEW_TEST_FAKE_CODEX"] = "1"
        env["FAKE_CODEX_PATH"] = str((self.fake_bin / "codex").resolve())
        env["CODEX_GH_COPILOT_COMPANION_PATH"] = str(
            (self.fake_bin / "copilot").resolve()
        )
        return env

    def _load_script_module(self):
        module_name = f"isolated_external_review_module_{time.time_ns()}"
        loader = importlib.machinery.SourceFileLoader(module_name, str(SCRIPT_PATH))
        spec = importlib.util.spec_from_loader(module_name, loader)
        if spec is None:
            raise AssertionError("failed to load isolated_external_review module spec")
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        return module

    def test_resolve_real_git_prefers_homebrew_git_before_apple_git(self) -> None:
        module = self._load_script_module()
        available = {"/opt/homebrew/bin/git", "/usr/bin/git"}
        attempted: list[str] = []

        def fake_run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
            attempted.append(cmd[0])
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout=b"git version 2.53.0\n",
                stderr=b"",
            )

        with mock.patch.object(
            module.os.path,
            "isfile",
            side_effect=lambda path: path in available,
        ), mock.patch.object(
            module.os,
            "access",
            side_effect=lambda path, mode: path in available,
        ), mock.patch.object(
            module.shutil,
            "which",
            return_value=None,
        ), mock.patch.object(module.subprocess, "run", side_effect=fake_run):
            resolved_git = module._resolve_real_git()

        self.assertIn("/opt/homebrew/", resolved_git)
        self.assertEqual(attempted, [resolved_git])

    def test_installed_readonly_git_shim_uses_absolute_python_shebang(self) -> None:
        module = self._load_script_module()

        shim_dir = module._install_readonly_git_shim(self.root / "shim-container")
        shim_path = shim_dir / "git"
        first_line = shim_path.read_text(encoding="utf-8").splitlines()[0]

        self.assertEqual(
            first_line,
            f"#!{module._resolve_python_for_readonly_git_shim()}",
        )
        self.assertNotIn("/usr/bin/env", first_line)

    def test_installed_readonly_git_shim_prefers_non_apple_python(self) -> None:
        module = self._load_script_module()
        homebrew_python = pathlib.Path("/opt/homebrew/bin/python3")
        resolved_homebrew_python = homebrew_python.resolve(strict=False)
        clt_python = "/Library/Developer/CommandLineTools/usr/bin/python3"

        with mock.patch.object(module.sys, "executable", clt_python):
            with mock.patch.object(
                module.shutil,
                "which",
                return_value=str(homebrew_python),
            ), mock.patch.object(
                module.pathlib.Path,
                "is_file",
                return_value=True,
            ), mock.patch.object(
                module.os,
                "access",
                return_value=True,
            ):
                shim_dir = module._install_readonly_git_shim(
                    self.root / "shim-container"
                )

        shim_path = shim_dir / "git"
        first_line = shim_path.read_text(encoding="utf-8").splitlines()[0]

        self.assertEqual(first_line, f"#!{resolved_homebrew_python}")
        self.assertNotEqual(first_line, f"#!{clt_python}")
        self.assertNotIn("/usr/bin/env", first_line)

    def _copilot_only_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["PATH"] = f"{self.copilot_only_bin}{os.pathsep}{os.defpath}"
        return env

    def _gh_copilot_fallback_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["PATH"] = f"{self.gh_copilot_fallback_bin}{os.pathsep}{os.defpath}"
        return env

    def _shim_env(self, *, extra: dict[str, str] | None = None) -> dict[str, str]:
        real_git = shutil.which("git")
        if real_git is None:
            raise AssertionError("git is required for shim tests")
        env = os.environ.copy()
        env["CODEX_REAL_GIT"] = real_git
        if extra:
            env.update(extra)
        return env

    def _run_shim(
        self,
        *args: str,
        cwd: pathlib.Path | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return run(
            [sys.executable, str(SHIM_PATH), *args],
            cwd=cwd,
            env=env or self._shim_env(),
        )

    def test_syncs_root_and_submodule_and_cleans_up(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--prompt-file",
                str(self.repo / ".codex-tmp" / "review.prompt"),
                "--diff-file",
                str(self.repo / ".codex-tmp" / "review.diff"),
                "--",
                "--output",
                str(self.output_file),
                "{workspace}",
                "{prompt_file}",
                "{diff_file}",
                "{prompt_text}",
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        isolated_root = pathlib.Path(payload["cwd"])

        self.assertNotEqual(isolated_root, self.repo)
        self.assertFalse(isolated_root.exists(), "workspace should be cleaned up on success")
        self.assertEqual(payload["tool"], "agent")
        self.assertEqual(payload["entrypoint"], "agent")
        self.assertEqual(payload["root_tracked"], "root-dirty\n")
        self.assertEqual(payload["root_untracked"], "root-untracked\n")
        self.assertEqual(payload["sub_tracked"], "sub-dirty\n")
        self.assertEqual(payload["sub_untracked"], "sub-untracked\n")
        self.assertEqual(
            payload["sub_git_toplevel"],
            str(isolated_root / "deps/sub"),
        )
        self.assertIn("Review ", payload["prompt_text"])
        self.assertIn("review.diff", payload["prompt_text"])
        self.assertIn("review.diff", payload["prompt_file_content"])
        self.assertIn(payload["prompt_file"], payload["args"])
        self.assertIn(payload["diff_file"], payload["args"])

    def test_agent_auto_bootstraps_long_prompt_file(self) -> None:
        long_prompt = self.repo / ".codex-tmp" / "review-long.prompt"
        long_prompt.write_text(
            "Review the current change carefully.\n"
            + "Focus on correctness only. " * 32,
            encoding="utf-8",
        )
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--prompt-file",
                str(long_prompt),
                "--diff-file",
                str(self.repo / ".codex-tmp" / "review.diff"),
                "--report-path",
                ".codex-tmp/reports/bootstrap.md",
                "--prompt-inline-max-bytes",
                "64",
                "--",
                "--output",
                str(self.output_file),
                "{prompt_text}",
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["entrypoint"], "agent")
        self.assertEqual(payload["prompt_delivery"], "bootstrap")
        self.assertIsNone(payload["prompt_text"])
        bootstrap_arg = next(
            arg for arg in payload["args"] if payload["prompt_file"] in arg
        )
        self.assertIn("Read the review instructions in", bootstrap_arg)
        self.assertIn(payload["diff_file"], bootstrap_arg)
        self.assertIn(payload["report_file"], bootstrap_arg)
        self.assertIn(payload["final_reply"], bootstrap_arg)
        self.assertIn("Focus on correctness only.", payload["prompt_file_content"])

    def test_auto_prefers_agent_over_copilot(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "auto",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "agent")
        self.assertEqual(payload["entrypoint"], "agent")
        self.assertEqual(
            payload["args"][:7],
            [
                "--mode",
                "ask",
                "--model",
                "claude-opus-4-7-thinking-high",
                "--print",
                "--trust",
                "--output",
            ],
        )
        self.assertEqual(payload["git_policy"], "readonly-shim")
        self.assertTrue(payload["git_shim"])
        self.assertEqual(payload["git_resolved"], payload["git_shim"])

    def test_copilot_auto_keeps_inline_long_prompt_file(self) -> None:
        long_prompt = self.repo / ".codex-tmp" / "review-copilot-long.prompt"
        long_prompt.write_text(
            "Review the current change carefully.\n"
            + "Focus on correctness only. " * 32,
            encoding="utf-8",
        )
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "copilot",
                "--prompt-file",
                str(long_prompt),
                "--diff-file",
                str(self.repo / ".codex-tmp" / "review.diff"),
                "--prompt-inline-max-bytes",
                "64",
                "--",
                "--output",
                str(self.output_file),
                "{prompt_text}",
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["entrypoint"], "copilot")
        self.assertEqual(payload["prompt_delivery"], "inline")
        self.assertIn("Focus on correctness only.", payload["prompt_text"])
        self.assertEqual(payload["args"].count("--prompt"), 1)
        self.assertTrue(any("Focus on correctness only." in arg for arg in payload["args"]))

    def test_frozen_base_and_head_refs_ignore_live_worktree_drift(self) -> None:
        repo, base, head = self._create_review_range_repo("range-repo")
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(repo),
                "--base-ref",
                base,
                "--head-ref",
                head,
                "--entrypoint",
                "agent",
                "--prompt-file",
                str(repo / ".codex-tmp" / "range.prompt"),
                "--",
                "--output",
                str(self.output_file),
                "{prompt_text}",
                "{review_range}",
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        isolated_root = pathlib.Path(payload["cwd"])
        self.assertFalse(isolated_root.exists(), "workspace should be cleaned up on success")
        self.assertEqual(payload["review_base"], base)
        self.assertEqual(payload["review_head"], head)
        self.assertEqual(payload["review_range"], f"{base}..{head}")
        self.assertEqual(payload["root_tracked"], "root-head\n")
        self.assertEqual(payload["root_untracked"], None)
        self.assertIn(f"{base}..{head}", payload["args"])
        self.assertIn(base, payload["prompt_file_content"])
        self.assertIn(head, payload["prompt_file_content"])
        self.assertIn(f"{base}..{head}", payload["prompt_file_content"])
        self.assertIn("-root-base", payload["diff_file_content"])
        self.assertIn("+root-head", payload["diff_file_content"])

    def test_frozen_range_with_submodules_cleans_up_workspace(self) -> None:
        base = git(self.repo, "rev-parse", "HEAD~1").stdout.strip()
        head = git(self.repo, "rev-parse", "HEAD").stdout.strip()
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--base-ref",
                base,
                "--head-ref",
                head,
                "--entrypoint",
                "agent",
                "--prompt-file",
                str(self.repo / ".codex-tmp" / "review.prompt"),
                "--",
                "--output",
                str(self.output_file),
                "{prompt_text}",
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        isolated_root = pathlib.Path(payload["cwd"])
        self.assertFalse(isolated_root.exists(), "workspace should be cleaned up on success")
        self.assertEqual(payload["root_tracked"], "root-base\n")
        self.assertEqual(payload["sub_tracked"], "sub-base\n")

    def test_base_ref_requires_head_ref(self) -> None:
        repo, base, _head = self._create_review_range_repo("range-repo-missing-head")
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(repo),
                "--base-ref",
                base,
                "--entrypoint",
                "agent",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("--base-ref and --head-ref must be provided together", completed.stderr)

    def test_head_ref_requires_base_ref(self) -> None:
        repo, _base, head = self._create_review_range_repo("range-repo-missing-base")
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(repo),
                "--head-ref",
                head,
                "--entrypoint",
                "agent",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("--base-ref and --head-ref must be provided together", completed.stderr)

    def test_auto_falls_back_to_copilot_without_agent_defaults(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "auto",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=self._copilot_only_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "copilot")
        self.assertEqual(payload["entrypoint"], "copilot")
        self.assertNotIn("--mode", payload["args"])
        self.assertTrue(
            all(not arg.startswith("--model") for arg in payload["args"])
        )
        self.assertNotIn("--print", payload["args"])
        self.assertNotIn("--trust", payload["args"])

    def test_bounded_semantic_lane_auto_prefers_opencode(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "bounded-semantic",
                "--entrypoint",
                "auto",
                "--prompt-file",
                str(self.repo / ".codex-tmp" / "review.prompt"),
                "--diff-file",
                str(self.repo / ".codex-tmp" / "review.diff"),
                "--report-path",
                ".codex-tmp/opencode-review/report.md",
                "--",
                "--output",
                str(self.output_file),
                "{prompt_text}",
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "opencode")
        self.assertEqual(payload["entrypoint"], "opencode")
        self.assertEqual(payload["args"][0], "run")
        self.assertIn("-m", payload["args"])
        self.assertIn("github-copilot/claude-opus-4.7", payload["args"])
        self.assertIn("--format", payload["args"])
        self.assertIn("json", payload["args"])
        self.assertIn("--file", payload["args"])
        self.assertIn(payload["diff_file"], payload["args"])
        self.assertIn("--", payload["args"])
        self.assertEqual(
            payload["final_reply"],
            "WROTE .codex-tmp/opencode-review/report.md",
        )
        config = json.loads(payload["opencode_config_content"])
        self.assertEqual(config["compaction"]["auto"], False)
        self.assertEqual(config["autoupdate"], False)
        self.assertEqual(config["snapshot"], False)
        self.assertEqual(
            config["permission"]["edit"][".codex-tmp/opencode-review/report.md"],
            "allow",
        )
        report_parent = str(pathlib.Path(payload["report_file"]).parent)
        self.assertEqual(
            config["permission"]["bash"][f"mkdir -p {report_parent}"],
            "allow",
        )
        self.assertFalse(payload["opencode_config_dir"])
        self.assertFalse(payload["xdg_data_home"])

    def test_baseline_lane_auto_prefers_copilot(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "baseline",
                "--entrypoint",
                "auto",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "copilot")
        self.assertEqual(payload["entrypoint"], "copilot")
        self.assertNotIn("--mode", payload["args"])
        self.assertTrue(
            all(not arg.startswith("--model") for arg in payload["args"])
        )
        self.assertNotIn("--print", payload["args"])
        self.assertNotIn("--trust", payload["args"])

    def test_gh_copilot_injects_prompt_flag_for_noninteractive_prompt_text(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "gh-copilot",
                "--prompt-file",
                str(self.repo / ".codex-tmp" / "review.prompt"),
                "--diff-file",
                str(self.repo / ".codex-tmp" / "review.diff"),
                "--",
                "--output",
                str(self.output_file),
                "{prompt_text}",
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "gh")
        self.assertEqual(payload["entrypoint"], "gh-copilot")
        self.assertEqual(payload["args"].count("--prompt"), 1)
        self.assertIn("Review ", payload["prompt"])

    def test_gh_copilot_injects_prompt_flag_for_literal_noninteractive_prompt(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "gh-copilot",
                "--",
                "--output",
                str(self.output_file),
                "Review only the current change.",
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "gh")
        self.assertEqual(payload["entrypoint"], "gh-copilot")
        self.assertEqual(payload["args"].count("--prompt"), 1)
        self.assertEqual(payload["prompt"], "Review only the current change.")

    def test_copilot_injects_prompt_flag_for_noninteractive_prompt_text(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "copilot",
                "--prompt-file",
                str(self.repo / ".codex-tmp" / "review.prompt"),
                "--diff-file",
                str(self.repo / ".codex-tmp" / "review.diff"),
                "--",
                "--output",
                str(self.output_file),
                "{prompt_text}",
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "copilot")
        self.assertEqual(payload["entrypoint"], "copilot")
        self.assertEqual(payload["args"].count("--prompt"), 1)
        self.assertTrue(any("Review " in arg for arg in payload["args"]))

    def test_copilot_injects_prompt_flag_for_literal_noninteractive_prompt(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "copilot",
                "--",
                "--output",
                str(self.output_file),
                "Review only the current change.",
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "copilot")
        self.assertEqual(payload["entrypoint"], "copilot")
        self.assertEqual(payload["args"].count("--prompt"), 1)
        self.assertIn("Review only the current change.", payload["args"])

    def test_copilot_injects_prompt_flag_after_optional_value_flag_without_value(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "copilot",
                "--",
                "--output",
                str(self.output_file),
                "--share",
                "Review only the current change.",
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "copilot")
        self.assertEqual(payload["entrypoint"], "copilot")
        self.assertEqual(payload["args"].count("--prompt"), 1)
        self.assertIn("--share", payload["args"])
        self.assertIn("Review only the current change.", payload["args"])

    def test_copilot_injects_prompt_flag_after_required_value_option(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "copilot",
                "--",
                "--output",
                str(self.output_file),
                "--stream",
                "on",
                "Review only the current change.",
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "copilot")
        self.assertEqual(payload["entrypoint"], "copilot")
        self.assertEqual(payload["args"].count("--prompt"), 1)
        self.assertIn("--stream", payload["args"])
        self.assertIn("on", payload["args"])
        self.assertIn("Review only the current change.", payload["args"])

    def test_baseline_auto_injects_prompt_flag_for_literal_prompt(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "baseline",
                "--entrypoint",
                "auto",
                "--",
                "--output",
                str(self.output_file),
                "Review only the current change.",
            ],
            env=self._copilot_only_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "copilot")
        self.assertEqual(payload["entrypoint"], "copilot")
        self.assertEqual(payload["args"].count("--prompt"), 1)
        self.assertIn("Review only the current change.", payload["args"])

    def test_bounded_semantic_lane_falls_back_when_opencode_preflight_fails(self) -> None:
        env = self._base_env()
        env["FAKE_OPENCODE_MODELS_FAIL"] = "1"
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "bounded-semantic",
                "--entrypoint",
                "auto",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "agent")
        self.assertEqual(payload["entrypoint"], "agent")

    def test_bounded_semantic_lane_falls_back_when_opencode_4_7_model_is_missing(self) -> None:
        env = self._base_env()
        env["FAKE_OPENCODE_HIDE_MODELS"] = "github-copilot/claude-opus-4.7"
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "bounded-semantic",
                "--entrypoint",
                "auto",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "agent")
        self.assertEqual(payload["entrypoint"], "agent")
        self.assertNotIn("github-copilot/claude-opus-4.7", payload["args"])

    def test_bounded_semantic_lane_accepts_provider_scoped_bare_opencode_models(self) -> None:
        env = self._base_env()
        env["FAKE_OPENCODE_SCOPE_BARE_MODELS"] = "1"
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "bounded-semantic",
                "--entrypoint",
                "auto",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "opencode")
        self.assertEqual(payload["entrypoint"], "opencode")
        self.assertIn("github-copilot/claude-opus-4.7", payload["args"])

    def test_bounded_semantic_lane_falls_back_when_supported_opencode_model_is_missing(
        self,
    ) -> None:
        env = self._base_env()
        env["FAKE_OPENCODE_HIDE_MODELS"] = "github-copilot/claude-opus-4.7"
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "bounded-semantic",
                "--entrypoint",
                "auto",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "agent")
        self.assertEqual(payload["entrypoint"], "agent")

    def test_deep_semantic_lane_falls_back_when_models_probe_is_inconclusive(self) -> None:
        env = self._base_env()
        env["FAKE_AGENT_MODELS_FAIL"] = "keychain"
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "deep-semantic",
                "--entrypoint",
                "auto",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "opencode")
        self.assertEqual(payload["entrypoint"], "opencode")

    def test_deep_semantic_lane_falls_back_when_agent_models_exec_fails(self) -> None:
        env = self._base_env()
        env["FAKE_AGENT_MODELS_FAIL"] = "exec"
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "deep-semantic",
                "--entrypoint",
                "auto",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "opencode")
        self.assertEqual(payload["entrypoint"], "opencode")

    def test_custom_lane_falls_back_when_default_agent_model_is_missing(self) -> None:
        env = self._base_env()
        env["FAKE_AGENT_HIDE_MODELS"] = (
            "claude-opus-4-7-thinking-high,"
            "claude-opus-4-7-high"
        )
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "custom",
                "--entrypoint",
                "auto",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "copilot")
        self.assertEqual(payload["entrypoint"], "copilot")

    def test_agent_defaults_fall_back_to_current_4_7_high_model_when_thinking_alias_is_missing(self) -> None:
        env = self._base_env()
        env["FAKE_AGENT_HIDE_MODELS"] = "claude-opus-4-7-thinking-high"
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "agent")
        self.assertEqual(payload["entrypoint"], "agent")
        self.assertIn("claude-opus-4-7-high", payload["args"])
        self.assertNotIn("claude-opus-4-7-thinking-high", payload["args"])

    def test_agent_default_run_fails_when_catalog_has_no_supported_4_7_alias(self) -> None:
        env = self._base_env()
        env["FAKE_AGENT_HIDE_MODELS"] = (
            "claude-opus-4-7-thinking-high,claude-opus-4-7-high"
        )
        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(
            "`agent` failed usability preflight: `agent models` did not list any supported helper default model",
            failed.stderr,
        )

    def test_agent_defaults_reuse_preflight_selected_compat_model(self) -> None:
        env = self._base_env()
        counter_file = self.root / "agent-models-count.txt"
        env["FAKE_AGENT_HIDE_MODELS"] = "claude-opus-4-7-thinking-high"
        env["FAKE_AGENT_MODELS_FAIL_AFTER_FIRST"] = "1"
        env["FAKE_AGENT_MODELS_COUNTER_FILE"] = str(counter_file)
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "agent")
        self.assertEqual(payload["entrypoint"], "agent")
        self.assertIn("claude-opus-4-7-high", payload["args"])
        self.assertEqual(counter_file.read_text(encoding="utf-8"), "1")

    def test_agent_inconclusive_preflight_can_recover_compat_model_at_launch(self) -> None:
        env = self._base_env()
        counter_file = self.root / "agent-models-first-fail-count.txt"
        env["FAKE_AGENT_HIDE_MODELS"] = "claude-opus-4-7-thinking-high"
        env["FAKE_AGENT_MODELS_FAIL_FIRST"] = "keychain"
        env["FAKE_AGENT_MODELS_COUNTER_FILE"] = str(counter_file)
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "agent")
        self.assertEqual(payload["entrypoint"], "agent")
        self.assertIn("claude-opus-4-7-high", payload["args"])
        self.assertEqual(counter_file.read_text(encoding="utf-8"), "2")

    def test_agent_short_model_override_is_not_shadowed_by_default_model(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--",
                "-m",
                "claude-opus-4-7-high",
                "--output",
                str(self.output_file),
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "agent")
        self.assertEqual(payload["entrypoint"], "agent")
        self.assertIn("-m", payload["args"])
        self.assertIn("claude-opus-4-7-high", payload["args"])
        self.assertNotIn("--model", payload["args"])
        self.assertNotIn("claude-opus-4-7-thinking-high", payload["args"])

    def test_agent_short_model_override_errors_when_requested_model_is_missing(self) -> None:
        env = self._base_env()
        env["FAKE_AGENT_HIDE_MODELS"] = "claude-opus-4-7-high"
        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--",
                "-m",
                "claude-opus-4-7-high",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(
            "`agent` failed usability preflight: `agent models` did not list `claude-opus-4-7-high`",
            failed.stderr,
        )

    def test_agent_default_run_fails_when_catalog_stays_inconclusive(self) -> None:
        env = self._base_env()
        env["FAKE_AGENT_MODELS_FAIL"] = "keychain"
        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(
            "unable to verify the helper default model after repeated inconclusive catalog probes",
            failed.stderr,
        )

    def test_deep_semantic_lane_falls_back_when_agent_catalog_stays_inconclusive(
        self,
    ) -> None:
        env = self._base_env()
        env["FAKE_AGENT_MODELS_FAIL"] = "keychain"
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "deep-semantic",
                "--entrypoint",
                "auto",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "opencode")
        self.assertEqual(payload["entrypoint"], "opencode")

    def test_deep_semantic_lane_falls_back_when_late_agent_catalog_lacks_supported_aliases(
        self,
    ) -> None:
        env = self._base_env()
        counter_file = self.root / "agent-models-late-fallback-count.txt"
        env["FAKE_AGENT_HIDE_MODELS"] = (
            "claude-opus-4-7-thinking-high,"
            "claude-opus-4-7-high"
        )
        env["FAKE_AGENT_MODELS_FAIL_FIRST"] = "keychain"
        env["FAKE_AGENT_MODELS_COUNTER_FILE"] = str(counter_file)
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "deep-semantic",
                "--entrypoint",
                "auto",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "opencode")
        self.assertEqual(payload["entrypoint"], "opencode")
        self.assertEqual(counter_file.read_text(encoding="utf-8"), "2")

    def test_deep_semantic_late_agent_fallback_strips_agent_only_args(self) -> None:
        env = self._base_env()
        counter_file = self.root / "agent-models-late-agent-args-count.txt"
        env["FAKE_AGENT_HIDE_MODELS"] = (
            "claude-opus-4-7-thinking-high,"
            "claude-opus-4-7-high"
        )
        env["FAKE_AGENT_MODELS_FAIL_FIRST"] = "keychain"
        env["FAKE_AGENT_MODELS_COUNTER_FILE"] = str(counter_file)
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "deep-semantic",
                "--entrypoint",
                "auto",
                "--",
                "--mode",
                "plan",
                "--trust",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "opencode")
        self.assertEqual(payload["entrypoint"], "opencode")
        self.assertNotIn("--mode", payload["args"])
        self.assertNotIn("plan", payload["args"])
        self.assertNotIn("--trust", payload["args"])
        self.assertEqual(counter_file.read_text(encoding="utf-8"), "2")

    def test_agent_inconclusive_preflight_fails_when_late_catalog_lacks_supported_aliases(
        self,
    ) -> None:
        env = self._base_env()
        counter_file = self.root / "agent-models-late-explicit-count.txt"
        env["FAKE_AGENT_HIDE_MODELS"] = (
            "claude-opus-4-7-thinking-high,"
            "claude-opus-4-7-high"
        )
        env["FAKE_AGENT_MODELS_FAIL_FIRST"] = "keychain"
        env["FAKE_AGENT_MODELS_COUNTER_FILE"] = str(counter_file)
        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(
            "`agent` failed usability preflight: `agent models` did not list any supported helper default model",
            failed.stderr,
        )
        self.assertEqual(counter_file.read_text(encoding="utf-8"), "2")

    def test_deep_semantic_late_agent_fallback_skips_external_gpt_model_override(self) -> None:
        env = self._base_env()
        counter_file = self.root / "agent-models-late-opencode-model-count.txt"
        env["FAKE_AGENT_HIDE_MODELS"] = (
            "claude-opus-4-7-thinking-high,"
            "claude-opus-4-7-high"
        )
        env["FAKE_AGENT_MODELS_FAIL_FIRST"] = "keychain"
        env["FAKE_AGENT_MODELS_COUNTER_FILE"] = str(counter_file)
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "deep-semantic",
                "--entrypoint",
                "auto",
                "--",
                "--model",
                "openai/gpt-5.3-codex",
                "--output",
                str(self.output_file),
                "--",
            ],
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "opencode")
        self.assertEqual(payload["entrypoint"], "opencode")
        self.assertNotIn("openai/gpt-5.3-codex", payload["args"])
        self.assertIn("github-copilot/claude-opus-4.7", payload["args"])
        self.assertEqual(counter_file.read_text(encoding="utf-8"), "2")

    def test_auto_gpt_model_override_participates_in_external_fallback_without_gpt(self) -> None:
        env = self._base_env()
        env["FAKE_OPENCODE_HIDE_MODELS"] = "openai/gpt-5.3-codex"
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "bounded-semantic",
                "--entrypoint",
                "auto",
                "--",
                "--model",
                "openai/gpt-5.3-codex",
                "--output",
                str(self.output_file),
                "--",
            ],
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "opencode")
        self.assertEqual(payload["entrypoint"], "opencode")
        self.assertIn("github-copilot/claude-opus-4.7", payload["args"])
        self.assertNotIn("openai/gpt-5.3-codex", payload["args"])

    def test_auto_gh_copilot_fallback_strips_external_gpt_model_override(self) -> None:
        env = self._gh_copilot_fallback_env()
        env["FAKE_OPENCODE_HIDE_MODELS"] = "github-copilot/claude-opus-4.7"
        env["FAKE_GH_REQUIRES_COPILOT"] = "1"
        env["CODEX_GH_COPILOT_COMPANION_PATH"] = str(self.fake_bin / "copilot")
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "bounded-semantic",
                "--entrypoint",
                "auto",
                "--prompt-file",
                str(self.repo / ".codex-tmp" / "review.prompt"),
                "--diff-file",
                str(self.repo / ".codex-tmp" / "review.diff"),
                "--",
                "--model",
                "openai/gpt-5.3-codex",
                "--output",
                str(self.output_file),
                "{prompt_text}",
                "--",
            ],
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "gh")
        self.assertEqual(payload["entrypoint"], "gh-copilot")
        self.assertTrue(
            all(not arg.startswith("--model") for arg in payload["args"])
        )
        self.assertNotIn("openai/gpt-5.3-codex", payload["args"])
        self.assertEqual(payload["args"].count("--prompt"), 1)

    def test_auto_agent_candidate_strips_bare_gpt_model_override(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "custom",
                "--entrypoint",
                "auto",
                "--",
                "--model",
                "gpt-5.3-codex",
                "--output",
                str(self.output_file),
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "agent")
        self.assertEqual(payload["entrypoint"], "agent")
        self.assertEqual(payload["args"].count("--model"), 1)
        self.assertIn("claude-opus-4-7-thinking-high", payload["args"])
        self.assertNotIn("gpt-5.3-codex", payload["args"])

    def test_explicit_opencode_entrypoint_rejects_gpt_model_override(self) -> None:
        env = self._base_env()
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "bounded-semantic",
                "--entrypoint",
                "opencode",
                "--",
                "--model",
                "openai/gpt-5.3-codex",
                "--output",
                str(self.output_file),
                "--",
            ],
            env=env,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("must not use GPT model", completed.stderr)

    def test_explicit_external_entrypoint_rejects_later_duplicate_gpt_model_override(self) -> None:
        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "bounded-semantic",
                "--entrypoint",
                "opencode",
                "--",
                "--model",
                "github-copilot/claude-opus-4.7",
                "--model",
                "openai/gpt-5.3-codex",
                "--output",
                str(self.output_file),
                "--",
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("must not use GPT model", failed.stderr)

    def test_explicit_agent_entrypoint_rejects_gpt_model_override(self) -> None:
        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--",
                "--model",
                "openai/gpt-5.3-codex",
                "--output",
                str(self.output_file),
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("must not use GPT model", failed.stderr)

    def test_explicit_copilot_entrypoint_rejects_gpt_model_override(self) -> None:
        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "copilot",
                "--",
                "--model",
                "gpt-5.3-codex",
                "--output",
                str(self.output_file),
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("must not use GPT model", failed.stderr)

    def test_explicit_gh_copilot_entrypoint_rejects_gpt_model_override(self) -> None:
        env = self._gh_copilot_fallback_env()
        env["CODEX_GH_COPILOT_COMPANION_PATH"] = str(self.fake_bin / "copilot")
        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "gh-copilot",
                "--",
                "--model",
                "gpt-5.3-codex",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("must not use GPT model", failed.stderr)

    def test_explicit_agent_entrypoint_errors_when_default_model_is_missing(self) -> None:
        env = self._base_env()
        env["FAKE_AGENT_HIDE_MODELS"] = (
            "claude-opus-4-7-thinking-high,"
            "claude-opus-4-7-high"
        )
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=env,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("`agent` failed usability preflight", completed.stderr)

    def test_super_large_lane_builds_hardened_opencode_config(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--lane",
                "super-large",
                "--entrypoint",
                "opencode",
                "--prompt-file",
                str(self.repo / ".codex-tmp" / "review.prompt"),
                "--diff-file",
                str(self.repo / ".codex-tmp" / "review.diff"),
                "--report-path",
                ".codex-tmp/opencode-review/report.md",
                "--opencode-reserved",
                "2048",
                "--",
                "--output",
                str(self.output_file),
                "{prompt_text}",
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        config = json.loads(payload["opencode_config_content"])
        self.assertEqual(config["compaction"]["auto"], True)
        self.assertEqual(config["compaction"]["prune"], False)
        self.assertEqual(config["compaction"]["reserved"], 2048)
        self.assertTrue(payload["xdg_data_home"])

    def test_final_reply_can_reference_default_final_reply(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--report-path",
                ".codex-tmp/reports/final.md",
                "--final-reply",
                "DONE: {final_reply}",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["report_file"].endswith(".codex-tmp/reports/final.md"), True)
        self.assertEqual(
            payload["final_reply"],
            "DONE: WROTE .codex-tmp/reports/final.md",
        )

    def test_explicit_agent_args_override_helper_defaults(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--",
                "--mode",
                "plan",
                "--model=gemini-3.1-pro",
                "--print",
                "--trust",
                "--output",
                str(self.output_file),
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "agent")
        self.assertEqual(payload["entrypoint"], "agent")
        self.assertEqual(payload["args"].count("--mode"), 1)
        self.assertEqual(payload["args"].count("--print"), 1)
        self.assertEqual(payload["args"].count("--trust"), 1)
        self.assertIn("plan", payload["args"])
        self.assertIn("--model=gemini-3.1-pro", payload["args"])
        self.assertNotIn("ask", payload["args"])
        self.assertNotIn("claude-opus-4-7-thinking-high", payload["args"])

    def test_partial_agent_override_keeps_remaining_defaults(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--",
                "--model=gemini-3.1-pro",
                "--output",
                str(self.output_file),
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "agent")
        self.assertEqual(payload["entrypoint"], "agent")
        self.assertEqual(payload["args"].count("--mode"), 1)
        self.assertEqual(payload["args"].count("--print"), 1)
        self.assertEqual(payload["args"].count("--trust"), 1)
        self.assertIn("ask", payload["args"])
        self.assertIn("--model=gemini-3.1-pro", payload["args"])
        self.assertNotIn("claude-opus-4-7-thinking-high", payload["args"])

    def test_legacy_alias_execs_new_helper(self) -> None:
        completed = run(
            [
                sys.executable,
                str(LEGACY_SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "agent")
        self.assertEqual(payload["entrypoint"], "agent")

    def test_compat_helper_path_execs_canonical_helper(self) -> None:
        completed = run(
            [
                sys.executable,
                str(COMPAT_HELPER_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "agent")
        self.assertEqual(payload["entrypoint"], "agent")

    def test_legacy_skill_path_wrapper_execs_new_helper(self) -> None:
        completed = run(
            [
                sys.executable,
                str(LEGACY_SKILL_SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "agent")
        self.assertEqual(payload["entrypoint"], "agent")

    def test_canonical_wrapper_is_self_contained_without_legacy_skill_dir(self) -> None:
        mirror_root = self.root / "canonical-only-review-skill"
        shutil.copytree(CANONICAL_SKILL_ROOT, mirror_root)

        completed = run(
            [
                sys.executable,
                str(mirror_root / "scripts" / "isolated_review"),
                "--help",
            ],
            env=self._base_env(),
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Create a detached review workspace", completed.stdout)

    def test_readonly_git_shim_allows_reads_blocks_mutation_and_strips_bypass_inputs(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--",
                "--output",
                str(self.output_file),
                "--probe-git-status",
                "--probe-git-diff",
                "--probe-git-commit",
                "--probe-git-config-diff",
                "--probe-git-env-diff",
                "--probe-git-exec-path",
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["git_policy"], "readonly-shim")
        self.assertEqual(payload["git_resolved"], payload["git_shim"])
        self.assertEqual(payload["git_status"]["returncode"], 0)
        self.assertEqual(payload["git_diff"]["returncode"], 0)
        self.assertEqual(payload["git_commit"]["returncode"], 126)
        self.assertIn(
            "readonly git shim blocked subcommand: commit",
            payload["git_commit"]["stderr"],
        )
        self.assertEqual(payload["git_config_diff"]["returncode"], 126)
        self.assertIn(
            "readonly git shim blocked global option: -c",
            payload["git_config_diff"]["stderr"],
        )
        self.assertEqual(payload["git_env_diff"]["returncode"], 0)
        self.assertNotIn("ENV_BYPASS", payload["git_env_diff"]["stdout"])
        self.assertEqual(payload["git_exec_path"]["returncode"], 126)
        self.assertIn(
            "readonly git shim blocked global option: --exec-path",
            payload["git_exec_path"]["stderr"],
        )

    def test_readonly_git_shim_keeps_cross_repo_history_access(self) -> None:
        other_repo = self._create_plain_repo("history-probe")

        log_completed = self._run_shim(
            "-C",
            str(other_repo),
            "log",
            "-1",
            "--oneline",
        )
        self.assertEqual(log_completed.returncode, 0, log_completed.stderr)
        self.assertIn("init history-probe", log_completed.stdout)

        head = git(other_repo, "rev-parse", "HEAD").stdout.strip()
        show_completed = self._run_shim(
            f"--git-dir={other_repo / '.git'}",
            f"--work-tree={other_repo}",
            "show",
            "-s",
            "--format=%H",
            "HEAD",
        )
        self.assertEqual(show_completed.returncode, 0, show_completed.stderr)
        self.assertEqual(show_completed.stdout.strip(), head)

        common_dir_completed = self._run_shim(
            f"--git-dir={other_repo / '.git'}",
            "--git-common-dir",
            str(other_repo / ".git"),
            f"--work-tree={other_repo}",
            "show",
            "-s",
            "--format=%H",
            "HEAD",
        )
        control_common_dir = run(
            [
                "git",
                f"--git-dir={other_repo / '.git'}",
                "--git-common-dir",
                str(other_repo / ".git"),
                f"--work-tree={other_repo}",
                "show",
                "-s",
                "--format=%H",
                "HEAD",
            ]
        )
        self.assertEqual(
            common_dir_completed.returncode,
            control_common_dir.returncode,
        )
        self.assertEqual(common_dir_completed.stdout, control_common_dir.stdout)
        self.assertEqual(common_dir_completed.stderr, control_common_dir.stderr)
        self.assertNotIn("readonly git shim blocked subcommand", common_dir_completed.stderr)

    def test_readonly_git_shim_strips_repo_routing_env(self) -> None:
        repo_a = self._create_plain_repo("routing-probe-a")
        repo_b = self._create_plain_repo("routing-probe-b")
        head_a = git(repo_a, "rev-parse", "HEAD").stdout.strip()
        head_b = git(repo_b, "rev-parse", "HEAD").stdout.strip()
        self.assertNotEqual(head_a, head_b)

        poisoned_env = self._shim_env(
            extra={
                "GIT_CEILING_DIRECTORIES": str(self.root),
                "GIT_COMMON_DIR": str(repo_b / ".git"),
                "GIT_DIR": str(repo_b / ".git"),
                "GIT_WORK_TREE": str(repo_b),
            }
        )
        control = run(
            [
                "git",
                "-C",
                str(repo_a),
                "rev-parse",
                "HEAD",
            ],
            env=poisoned_env,
        )
        self.assertEqual(control.returncode, 0, control.stderr)
        self.assertEqual(control.stdout.strip(), head_b)

        completed = self._run_shim(
            "-C",
            str(repo_a),
            "rev-parse",
            "HEAD",
            env=poisoned_env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), head_a)

    def test_readonly_git_shim_ignores_target_repo_hooks_path(self) -> None:
        trigger = self.root / "hooks-path-triggered"
        other_repo = self._create_hooks_path_repo(
            "hooks-path-probe",
            trigger=trigger,
        )

        control = git(other_repo, "status", "--short")
        self.assertEqual(control.returncode, 0, control.stderr)
        self.assertTrue(
            trigger.exists(),
            "control probe should show the repo-local hooks path is active",
        )
        trigger.unlink()

        completed = self._run_shim(
            "-C",
            str(other_repo),
            "status",
            "--short",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(" M file.txt", completed.stdout)
        self.assertFalse(trigger.exists())

    def test_readonly_git_shim_ignores_target_repo_diff_external(self) -> None:
        other_repo = self._create_plain_repo("diff-external-probe")
        (other_repo / "file.txt").write_text("changed\n", encoding="utf-8")
        self.assertEqual(
            git(other_repo, "config", "diff.external", "echo REPOCFG").returncode,
            0,
        )

        completed = self._run_shim(
            "-C",
            str(other_repo),
            "diff",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("REPOCFG", completed.stdout)
        self.assertIn("diff --git a/file.txt b/file.txt", completed.stdout)

    def test_readonly_git_shim_disables_target_repo_clean_filters(self) -> None:
        trigger = self.root / "filter-triggered"
        other_repo = self._create_filter_repo(
            "filter-probe",
            trigger=trigger,
        )

        control = git(other_repo, "status", "--short")
        self.assertEqual(control.returncode, 0, control.stderr)
        self.assertTrue(
            trigger.exists(),
            "control probe should show the repo-local clean filter is active",
        )
        trigger.unlink()

        status_completed = self._run_shim(
            "-C",
            str(other_repo),
            "status",
            "--short",
        )
        self.assertEqual(status_completed.returncode, 0, status_completed.stderr)
        self.assertIn(" M file.txt", status_completed.stdout)
        self.assertFalse(trigger.exists())

        diff_completed = self._run_shim(
            "-C",
            str(other_repo),
            "diff",
        )
        self.assertEqual(diff_completed.returncode, 0, diff_completed.stderr)
        self.assertIn("diff --git a/file.txt b/file.txt", diff_completed.stdout)
        self.assertFalse(trigger.exists())

    def test_readonly_git_shim_disables_target_repo_clean_filters_for_blame(self) -> None:
        trigger = self.root / "blame-filter-triggered"
        other_repo = self._create_filter_repo(
            "blame-filter-probe",
            trigger=trigger,
        )

        control = git(other_repo, "blame", "file.txt")
        self.assertEqual(control.returncode, 0, control.stderr)
        self.assertTrue(
            trigger.exists(),
            "control probe should show the repo-local clean filter is active",
        )
        trigger.unlink()

        completed = self._run_shim(
            "-C",
            str(other_repo),
            "blame",
            "file.txt",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("changed", completed.stdout)
        self.assertFalse(trigger.exists())

    def test_readonly_git_shim_disables_target_repo_clean_filters_with_equals_in_driver_name(self) -> None:
        trigger = self.root / "equals-filter-triggered"
        other_repo = self._create_filter_repo(
            "equals-filter-probe",
            trigger=trigger,
            driver="a=b",
        )

        control = git(other_repo, "status", "--short")
        self.assertEqual(control.returncode, 0, control.stderr)
        self.assertTrue(
            trigger.exists(),
            "control probe should show the repo-local clean filter is active",
        )
        trigger.unlink()

        completed = self._run_shim(
            "-C",
            str(other_repo),
            "status",
            "--short",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(" M file.txt", completed.stdout)
        self.assertFalse(trigger.exists())

    def test_readonly_git_shim_blocks_ext_diff_flag(self) -> None:
        other_repo = self._create_diff_driver_repo("ext-diff-probe")

        control = git(other_repo, "diff", "--ext-diff")
        self.assertEqual(control.returncode, 0, control.stderr)
        self.assertIn("EXTDIFF_TRIGGER", control.stdout)

        completed = self._run_shim(
            "-C",
            str(other_repo),
            "diff",
            "--ext-diff",
            "HEAD",
        )
        self.assertEqual(completed.returncode, 126)
        self.assertIn(
            "readonly git shim blocked subcommand option: --ext-diff",
            completed.stderr,
        )
        self.assertNotIn("EXTDIFF_TRIGGER", completed.stdout)

    def test_readonly_git_shim_blocks_open_files_in_pager_flag(self) -> None:
        other_repo = self._create_plain_repo("grep-open-in-pager-probe", initial_content="needle\n")

        control = git(
            other_repo,
            "grep",
            "--open-files-in-pager=echo GREP_TRIGGER",
            "needle",
        )
        self.assertEqual(control.returncode, 0, control.stderr)
        self.assertIn("GREP_TRIGGER", control.stdout)

        completed = self._run_shim(
            "-C",
            str(other_repo),
            "grep",
            "--open-files-in-pager=echo GREP_TRIGGER",
            "needle",
        )
        self.assertEqual(completed.returncode, 126)
        self.assertIn(
            "readonly git shim blocked subcommand option: --open-files-in-pager",
            completed.stderr,
        )
        self.assertNotIn("GREP_TRIGGER", completed.stdout)

        short_completed = self._run_shim(
            "-C",
            str(other_repo),
            "grep",
            "-O",
            "echo GREP_TRIGGER",
            "--",
            "needle",
        )
        self.assertEqual(short_completed.returncode, 126)
        self.assertIn(
            "readonly git shim blocked subcommand option: --open-files-in-pager",
            short_completed.stderr,
        )
        self.assertNotIn("GREP_TRIGGER", short_completed.stdout)

    def test_readonly_git_shim_allows_grep_pattern_value_starting_with_blocked_short_alias(self) -> None:
        other_repo = self._create_plain_repo(
            "grep-pattern-short-alias-probe",
            initial_content="-OOPS pattern\n",
        )

        control = git(
            other_repo,
            "grep",
            "-n",
            "-e",
            "-OOPS",
            "--",
            "file.txt",
        )
        self.assertEqual(control.returncode, 0, control.stderr)
        self.assertIn("file.txt:1:-OOPS pattern", control.stdout)

        completed = self._run_shim(
            "-C",
            str(other_repo),
            "grep",
            "-n",
            "-e",
            "-OOPS",
            "--",
            "file.txt",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, control.stdout)
        self.assertEqual(completed.stderr, control.stderr)

    def test_readonly_git_shim_blocks_other_dangerous_reader_flags(self) -> None:
        other_repo = self._create_diff_driver_repo("reader-flag-probe")

        cases = [
            (
                "show",
                "--textconv",
                ["show", "--textconv", "HEAD:file.txt"],
            ),
            (
                "cat-file",
                "--filters",
                ["cat-file", "--filters", "blob", "HEAD:file.txt"],
            ),
        ]

        for _subcommand, blocked_flag, argv in cases:
            with self.subTest(flag=blocked_flag):
                completed = self._run_shim(
                    "-C",
                    str(other_repo),
                    *argv,
                )
                self.assertEqual(completed.returncode, 126)
                self.assertIn(
                    f"readonly git shim blocked subcommand option: {blocked_flag}",
                    completed.stderr,
                )

    def test_readonly_git_shim_preserves_diff_no_index_outside_repo(self) -> None:
        scratch = self.root / "no-index-probe"
        scratch.mkdir()
        left = scratch / "left.txt"
        right = scratch / "right.txt"
        left.write_text("left\n", encoding="utf-8")
        right.write_text("right\n", encoding="utf-8")

        argv = [
            "-C",
            str(scratch),
            "diff",
            "--no-index",
            str(left),
            str(right),
        ]
        control = run(["git", *argv])
        completed = self._run_shim(*argv)

        self.assertEqual(completed.returncode, control.returncode)
        self.assertEqual(completed.stdout, control.stdout)
        self.assertEqual(completed.stderr, control.stderr)
        self.assertNotIn(
            "readonly git shim could not inspect local filter config",
            completed.stderr,
        )

    def test_readonly_git_shim_clears_repo_local_gpg_program_for_signature_reads(self) -> None:
        other_repo, rev = self._create_fake_signed_repo("gpg-program-probe")

        control = self._run_git_show_signature(other_repo, rev)
        self.assertEqual(control.returncode, 0, control.stderr)
        self.assertIn("GPG_TRIGGER", control.stdout + control.stderr)

        completed = self._run_shim(
            "-C",
            str(other_repo),
            "show",
            "--show-signature",
            "--no-patch",
            rev,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("GPG_TRIGGER", completed.stdout + completed.stderr)

    def test_legacy_entrypoint_does_not_get_agent_defaults(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "copilot",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "copilot")
        self.assertEqual(payload["entrypoint"], "copilot")
        self.assertNotIn("--mode", payload["args"])
        self.assertTrue(
            all(not arg.startswith("--model") for arg in payload["args"])
        )
        self.assertNotIn("--print", payload["args"])
        self.assertNotIn("--trust", payload["args"])

    def test_keeps_workspace_on_failure_when_requested(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--keep-on-failure",
                "--",
                "--output",
                str(self.failure_file),
                "--fail",
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 7, completed.stderr)
        payload = json.loads(self.failure_file.read_text(encoding="utf-8"))
        isolated_root = pathlib.Path(payload["cwd"])
        self.assertTrue(isolated_root.exists(), "workspace should be kept on failure")

    def test_skips_uninitialized_source_submodule(self) -> None:
        deinit = run(
            [
                "git",
                "-C",
                str(self.repo),
                "submodule",
                "deinit",
                "-f",
                "deps/sub",
            ]
        )
        self.assertEqual(deinit.returncode, 0, deinit.stderr)

        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "agent")
        self.assertEqual(payload["entrypoint"], "agent")

    def test_prepare_only_then_reuse_workspace(self) -> None:
        prepare = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--prepare-only",
            ],
            env=self._base_env(),
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)

        lines = [
            line.strip()
            for line in prepare.stdout.splitlines()
            if line.strip()
        ]
        self.assertTrue(lines, prepare.stdout)
        workspace_root = pathlib.Path(lines[-1])
        self.assertTrue(workspace_root.exists())

        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--reuse-workspace",
                str(workspace_root),
                "--entrypoint",
                "agent",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "agent")
        self.assertEqual(payload["cwd"], str(workspace_root))
        self.assertEqual(
            payload["sub_git_toplevel"],
            str(workspace_root / "deps/sub"),
        )

    def test_validate_reused_workspace_accepts_source_root_symlink_alias(self) -> None:
        module = self._load_script_module()
        real_root = self.root / "reused-workspace-real-root"
        real_workspace = real_root / ".codex-tmp" / "workspace"
        real_workspace.mkdir(parents=True)
        alias_root = self.root / "reused-workspace-alias"
        os.symlink(real_root, alias_root)

        with mock.patch.object(module, "_is_git_worktree_root", return_value=True):
            resolved_workspace = module._validate_reused_workspace(
                alias_root / ".codex-tmp" / "workspace",
                source_root=alias_root,
                expected_head=None,
            )

        self.assertEqual(resolved_workspace, real_workspace.resolve(strict=False))

    def test_prepare_only_uncommitted_workspace_preserves_git_tracking(self) -> None:
        repo = self._create_plain_repo("prepare-uncommitted-tracking")
        (repo / "file.txt").write_text("dirty\n", encoding="utf-8")
        (repo / "notes.txt").write_text("untracked\n", encoding="utf-8")

        prepare = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(repo),
                "--prepare-only",
            ],
            env=self._base_env(),
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)

        workspace_root = pathlib.Path(
            [line.strip() for line in prepare.stdout.splitlines() if line.strip()][-1]
        )
        tracked = git(workspace_root, "ls-files", "-s").stdout
        self.assertIn("file.txt", tracked)
        status = git(workspace_root, "status", "--short", "--untracked-files=all").stdout
        self.assertIn(" M file.txt", status)
        self.assertIn("?? notes.txt", status)
        self.assertNotIn("D  file.txt", status)

    def test_prepare_only_uncommitted_workspace_preserves_tracked_deletion(self) -> None:
        repo = self._create_plain_repo("prepare-uncommitted-deletion")
        (repo / "file.txt").unlink()

        prepare = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(repo),
                "--prepare-only",
            ],
            env=self._base_env(),
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)

        workspace_root = pathlib.Path(
            [line.strip() for line in prepare.stdout.splitlines() if line.strip()][-1]
        )
        status = git(workspace_root, "status", "--short", "--untracked-files=all").stdout
        self.assertIn(" D file.txt", status)
        diff = git(workspace_root, "diff", "--binary", "HEAD", "--", "file.txt").stdout
        self.assertIn("deleted file mode", diff)

    def test_generated_uncommitted_diff_includes_untracked_file_content(self) -> None:
        module = self._load_script_module()
        repo = self._create_plain_repo("prepare-untracked-diff")
        (repo / "new.txt").write_text("brand new\n", encoding="utf-8")

        prepare = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(repo),
                "--prepare-only",
            ],
            env=self._base_env(),
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)

        workspace_root = pathlib.Path(
            [line.strip() for line in prepare.stdout.splitlines() if line.strip()][-1]
        )
        diff_path = module._write_generated_uncommitted_review_diff(
            target_root=workspace_root,
        )
        diff_text = diff_path.read_text(encoding="utf-8")
        self.assertIn("?? new.txt", diff_text)
        self.assertIn("diff --git a/new.txt b/new.txt", diff_text)
        self.assertIn("+brand new", diff_text)

    def test_generated_uncommitted_diff_recurses_into_dirty_submodules(self) -> None:
        module = self._load_script_module()
        prepare = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--prepare-only",
            ],
            env=self._base_env(),
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)

        workspace_root = pathlib.Path(
            [line.strip() for line in prepare.stdout.splitlines() if line.strip()][-1]
        )
        diff_path = module._write_generated_uncommitted_review_diff(
            target_root=workspace_root,
        )
        diff_text = diff_path.read_text(encoding="utf-8")
        self.assertIn("# Working tree status vs HEAD (deps/sub)", diff_text)
        self.assertIn("scratch.txt", diff_text)
        self.assertIn("+sub-untracked", diff_text)

    def test_generated_uncommitted_diff_ignores_external_diff_config(self) -> None:
        module = self._load_script_module()
        repo = self._create_plain_repo("prepare-external-diff")
        self.assertEqual(
            git(repo, "config", "diff.external", "echo EXTERNAL_TRIGGER").returncode,
            0,
        )
        (repo / "file.txt").write_text("changed\n", encoding="utf-8")

        diff_path = module._write_generated_uncommitted_review_diff(
            target_root=repo,
        )
        diff_text = diff_path.read_text(encoding="utf-8")
        self.assertIn("diff --git a/file.txt b/file.txt", diff_text)
        self.assertNotIn("EXTERNAL_TRIGGER", diff_text)

    def test_generated_uncommitted_diff_ignores_textconv_config(self) -> None:
        module = self._load_script_module()
        repo = self._create_plain_repo("prepare-textconv")
        self.assertEqual(
            git(repo, "config", "diff.pwned.textconv", "echo TEXTCONV_TRIGGER").returncode,
            0,
        )
        (repo / ".gitattributes").write_text("file.txt diff=pwned\n", encoding="utf-8")
        self.assertEqual(git(repo, "add", ".gitattributes").returncode, 0)
        git_commit(repo, "add textconv attrs")
        (repo / "file.txt").write_text("changed\n", encoding="utf-8")

        diff_path = module._write_generated_uncommitted_review_diff(
            target_root=repo,
        )
        diff_text = diff_path.read_text(encoding="utf-8")
        self.assertIn("diff --git a/file.txt b/file.txt", diff_text)
        self.assertNotIn("TEXTCONV_TRIGGER", diff_text)

    def test_prepare_only_uses_trusted_real_git_when_path_is_poisoned(self) -> None:
        poison_bin = self.root / "poison-bin"
        poison_bin.mkdir()
        poison_git = poison_bin / "git"
        poison_git.write_text(
            "#!/bin/sh\necho POISON_GIT >&2\nexit 42\n",
            encoding="utf-8",
        )
        poison_git.chmod(0o755)

        env = self._base_env()
        env["PATH"] = f"{poison_bin}{os.pathsep}{env['PATH']}"
        prepare = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--prepare-only",
            ],
            env=env,
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        self.assertNotIn("POISON_GIT", prepare.stderr)

        lines = [line.strip() for line in prepare.stdout.splitlines() if line.strip()]
        self.assertTrue(lines, prepare.stdout)
        workspace_root = pathlib.Path(lines[-1])
        self.assertTrue(workspace_root.exists())

    def test_codex_review_uses_trusted_real_codex_when_path_is_poisoned(self) -> None:
        poison_bin = self.root / "poison-codex-bin"
        poison_bin.mkdir()
        poison_codex = poison_bin / "codex"
        poison_codex.write_text(
            "#!/bin/sh\necho POISON_CODEX >&2\nexit 42\n",
            encoding="utf-8",
        )
        poison_codex.chmod(0o755)

        env = self._base_env()
        env["PATH"] = f"{poison_bin}{os.pathsep}{env['PATH']}"
        start = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(self.repo),
                "--entrypoint",
                "codex-review",
            ],
            env=env,
        )
        self.assertEqual(start.returncode, 0, start.stderr)
        state_dir = pathlib.Path(start.stdout.strip().splitlines()[-1])

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)
        self.assertNotIn("POISON_CODEX", waited.stderr)

        stdout_lines = (state_dir / "stdout.log").read_text(encoding="utf-8").splitlines()
        payload = json.loads(stdout_lines[-1])["payload"]
        self.assertEqual(
            payload["argv0"],
            str((self.fake_bin / "codex").resolve()),
        )

    def test_codex_review_start_wait_final_uses_readonly_root_session(self) -> None:
        env = self._base_env()
        env["FAKE_CODEX_PROBE_GIT_COMMIT"] = "1"
        repo, base, head = self._create_review_range_repo("codex-range-review")
        start = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(repo),
                "--entrypoint",
                "codex-review",
                "--base-ref",
                base,
                "--head-ref",
                head,
            ],
            env=env,
        )
        self.assertEqual(start.returncode, 0, start.stderr)
        state_dir = pathlib.Path(start.stdout.strip().splitlines()[-1])
        self.assertTrue(state_dir.exists())

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)
        summary = json.loads(waited.stdout)
        self.assertEqual(summary["status"], "passed")
        self.assertFalse((state_dir / "workspace").exists())

        stdout_lines = (state_dir / "stdout.log").read_text(encoding="utf-8").splitlines()
        payload = json.loads(stdout_lines[-1])["payload"]
        self.assertEqual(payload["tool"], "codex")
        self.assertEqual(payload["sandbox"], "read-only")
        self.assertEqual(payload["review_base"], base)
        self.assertTrue(payload["used_review_subcommand"])
        self.assertIn("review", payload["args"])
        self.assertEqual(payload["review_args"][:2], ["--base", base])
        self.assertIsNone(payload["prompt_stdin"])
        self.assertIn("--add-dir", payload["args"])
        self.assertEqual(payload["tmpdir"], payload["tmp"])
        self.assertEqual(payload["tmpdir"], payload["temp"])
        self.assertTrue(payload["tmpdir"].endswith("codex-review-tmp"))
        self.assertTrue(payload["tmpprefix"].endswith("codex-review-tmp/zsh"))
        self.assertEqual(payload["git_policy"], "readonly-shim")
        self.assertEqual(payload["git_resolved"], payload["git_shim"])
        self.assertEqual(payload["git_commit"]["returncode"], 126)
        self.assertIn(
            "readonly git shim blocked subcommand: commit",
            payload["git_commit"]["stderr"],
        )

        final = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "final",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(final.returncode, 0, final.stderr)
        self.assertEqual(final.stdout, "No findings.\n")

    def test_stateful_opencode_start_uses_default_prompt_for_frozen_range(self) -> None:
        env = self._base_env()
        env["FAKE_REVIEW_OUTPUT_FILE"] = str(self.output_file)
        repo, base, head = self._create_review_range_repo("opencode-default-prompt")

        start = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(repo),
                "--entrypoint",
                "opencode",
                "--base-ref",
                base,
                "--head-ref",
                head,
            ],
            env=env,
        )

        self.assertEqual(start.returncode, 0, start.stderr)
        state_dir = pathlib.Path(start.stdout.strip().splitlines()[-1])

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )

        self.assertEqual(waited.returncode, 0, waited.stderr)
        summary = json.loads(waited.stdout)
        self.assertEqual(summary["status"], "passed")

        payload = json.loads(self.output_file.read_text(encoding="utf-8"))
        prompt_text = payload["prompt_text"]
        self.assertEqual(payload["tool"], "opencode")
        self.assertEqual(payload["entrypoint"], "opencode")
        self.assertEqual(payload["prompt_delivery"], "inline")
        self.assertIsNotNone(prompt_text)
        self.assertIn("Review the provided diff", prompt_text)
        self.assertIn("Evidence budget:", prompt_text)
        self.assertIn("git diff --unified=30/40/50/60/80", prompt_text)
        self.assertIn(payload["diff_file"], prompt_text)
        self.assertIn(f"{base}..{head}", prompt_text)
        self.assertIn("No findings.", prompt_text)
        self.assertEqual(payload["args"][0], "run")
        self.assertIn("--file", payload["args"])
        self.assertIn(payload["diff_file"], payload["args"])
        self.assertIn(prompt_text, payload["args"])

    def test_codex_readonly_start_wait_final_uses_stdin_prompt(self) -> None:
        env = self._base_env()
        env["FAKE_CODEX_FINAL_MESSAGE_CODEX_READONLY"] = "Readonly findings.\n"
        repo, base, head = self._create_review_range_repo("codex-readonly-range")
        start = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(repo),
                "--entrypoint",
                "codex-readonly",
                "--base-ref",
                base,
                "--head-ref",
                head,
            ],
            env=env,
        )
        self.assertEqual(start.returncode, 0, start.stderr)
        state_dir = pathlib.Path(start.stdout.strip().splitlines()[-1])

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)
        summary = json.loads(waited.stdout)
        self.assertEqual(summary["status"], "passed")

        stdout_lines = (state_dir / "stdout.log").read_text(encoding="utf-8").splitlines()
        payload = json.loads(stdout_lines[-1])["payload"]
        self.assertEqual(payload["tool"], "codex")
        self.assertEqual(payload["sandbox"], "read-only")
        self.assertFalse(payload["used_review_subcommand"])
        self.assertEqual(payload["review_base"], base)
        self.assertIsNotNone(payload["prompt_stdin"])
        self.assertIn("Persistent internal Codex readonly review contract:", payload["prompt_stdin"])
        self.assertIn("Frozen review range:", payload["prompt_stdin"])
        self.assertIn("Start with changed-file lists", payload["prompt_stdin"])
        self.assertIn("git diff --unified=30/40/50/60/80", payload["prompt_stdin"])
        self.assertIn("--add-dir", payload["args"])
        self.assertTrue(payload["tmpdir"].endswith("codex-readonly-tmp"))
        self.assertEqual(payload["git_policy"], "readonly-shim")
        self.assertEqual(payload["git_resolved"], payload["git_shim"])
        self.assertTrue(payload["diff_file"].endswith(".diff"))
        self.assertIn(
            str(pathlib.Path(payload["final_file"]).resolve(strict=False).parent),
            payload["args"],
        )

        final = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "final",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(final.returncode, 0, final.stderr)
        self.assertEqual(final.stdout, "Readonly findings.\n")

    def test_codex_readonly_one_shot_prints_normalized_final_before_cleanup(self) -> None:
        env = self._base_env()
        repo, base, head = self._create_review_range_repo("codex-readonly-one-shot")

        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(repo),
                "--entrypoint",
                "codex-readonly",
                "--base-ref",
                base,
                "--head-ref",
                head,
            ],
            env=env,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "LGTM\n")

    def test_codex_readonly_stateful_final_normalizes_no_findings(self) -> None:
        env = self._base_env()
        repo, base, head = self._create_review_range_repo("codex-readonly-stateful-default")

        start = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(repo),
                "--entrypoint",
                "codex-readonly",
                "--base-ref",
                base,
                "--head-ref",
                head,
            ],
            env=env,
        )
        self.assertEqual(start.returncode, 0, start.stderr)
        state_dir = pathlib.Path(start.stdout.strip().splitlines()[-1])

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)

        final = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "final",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(final.returncode, 0, final.stderr)
        self.assertEqual(final.stdout, "LGTM\n")

    def test_codex_parallel_start_wait_final_aggregates_lanes(self) -> None:
        env = self._base_env()
        env["FAKE_CODEX_FINAL_MESSAGE_CODEX_READONLY"] = "Readonly findings.\n"
        env["FAKE_CODEX_FINAL_MESSAGE_CODEX_REVIEW"] = "Agentic findings.\n"
        repo, base, head = self._create_review_range_repo("codex-parallel-range")
        start = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(repo),
                "--entrypoint",
                "codex-parallel",
                "--base-ref",
                base,
                "--head-ref",
                head,
            ],
            env=env,
        )
        self.assertEqual(start.returncode, 0, start.stderr)
        state_dir = pathlib.Path(start.stdout.strip().splitlines()[-1])

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)
        summary = json.loads(waited.stdout)
        self.assertEqual(summary["entrypoint"], "codex-parallel")
        self.assertEqual(summary["status"], "passed")
        self.assertTrue(summary["final_available"])
        self.assertTrue(summary["report_available"])
        self.assertIn("readonly", summary["children"])
        self.assertIn("agentic", summary["children"])
        self.assertEqual(summary["children"]["readonly"]["status"], "passed")
        self.assertEqual(summary["children"]["agentic"]["status"], "passed")
        self.assertTrue(summary["workspace_cleaned"])
        self.assertFalse(pathlib.Path(summary["workspace_root"]).exists())

        readonly_state = json.loads(
            (
                pathlib.Path(summary["children"]["readonly"]["state_dir"])
                / "state.json"
            ).read_text(encoding="utf-8")
        )
        agentic_state = json.loads(
            (
                pathlib.Path(summary["children"]["agentic"]["state_dir"])
                / "state.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(readonly_state["workspace_root"], agentic_state["workspace_root"])
        self.assertEqual(readonly_state["workspace_root"], summary["workspace_root"])

        final = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "final",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(final.returncode, 0, final.stderr)
        self.assertIn("# Internal Review Report", final.stdout)
        self.assertIn("## Readonly", final.stdout)
        self.assertIn("Readonly findings.", final.stdout)
        self.assertIn("## Agentic", final.stdout)
        self.assertIn("Agentic findings.", final.stdout)

    def test_codex_parallel_treats_agentic_failure_as_advisory(self) -> None:
        env = self._base_env()
        env["FAKE_CODEX_FINAL_MESSAGE_CODEX_READONLY"] = "Readonly findings.\n"
        env["FAKE_CODEX_FAIL_ENTRYPOINTS"] = "codex-review"
        repo, base, head = self._create_review_range_repo("codex-parallel-advisory")
        start = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(repo),
                "--entrypoint",
                "codex-parallel",
                "--base-ref",
                base,
                "--head-ref",
                head,
            ],
            env=env,
        )
        self.assertEqual(start.returncode, 0, start.stderr)
        state_dir = pathlib.Path(start.stdout.strip().splitlines()[-1])

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)
        summary = json.loads(waited.stdout)
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["children"]["readonly"]["status"], "passed")
        self.assertEqual(summary["children"]["agentic"]["status"], "failed")

        final = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "final",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(final.returncode, 0, final.stderr)
        self.assertIn("Readonly findings.", final.stdout)
        self.assertIn("## Agentic", final.stdout)
        self.assertIn("Inconclusive:", final.stdout)

    def test_codex_parallel_uncommitted_readonly_diff_lives_in_child_state_dir(self) -> None:
        start = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(self.repo),
                "--entrypoint",
                "codex-parallel",
            ],
            env=self._base_env(),
        )
        self.assertEqual(start.returncode, 0, start.stderr)
        state_dir = pathlib.Path(start.stdout.strip().splitlines()[-1]).resolve()

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)
        summary = json.loads(waited.stdout)
        readonly_state_dir = pathlib.Path(
            summary["children"]["readonly"]["state_dir"]
        ).resolve()
        shared_workspace_root = pathlib.Path(summary["workspace_root"]).resolve(strict=False)

        stdout_lines = (readonly_state_dir / "stdout.log").read_text(encoding="utf-8").splitlines()
        payload = json.loads(stdout_lines[-1])["payload"]
        diff_file = pathlib.Path(payload["diff_file"]).resolve(strict=False)
        self.assertTrue(diff_file.exists())
        self.assertTrue(
            diff_file.is_relative_to(readonly_state_dir.resolve(strict=False))
        )
        self.assertFalse(diff_file.is_relative_to(shared_workspace_root))
        self.assertIn(str(diff_file.parent), payload["args"])
        diff_text = diff_file.read_text(encoding="utf-8")
        self.assertIn("?? notes.txt", diff_text)
        self.assertIn("+root-untracked", diff_text)

    def test_codex_parallel_rejects_helper_managed_customizations(self) -> None:
        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(self.repo),
                "--entrypoint",
                "codex-parallel",
                "--diff-file",
                str(self.repo / ".codex-tmp" / "review.diff"),
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("codex-parallel is fully helper-managed", failed.stderr)
        self.assertIn("--diff-file", failed.stderr)

    def test_codex_parallel_readonly_start_failure_cleans_shared_workspace(self) -> None:
        module = self._load_script_module()
        real_git = module._resolve_real_git()
        source_root = self._create_plain_repo("parallel-readonly-start-failure")
        shared_container = source_root / ".codex-tmp" / "shared-workspace"
        shared_workspace = shared_container / "workspace"
        shared_workspace.mkdir(parents=True)
        args = argparse.Namespace(
            repo=str(source_root),
            base_ref=None,
            head_ref=None,
            lane="custom",
            keep_on_failure=False,
            keep_workspace=False,
            reuse_workspace=None,
            prompt_file=None,
            diff_file=None,
            copy_path=[],
            report_path=None,
            final_reply=None,
            prompt_delivery="auto",
            prompt_inline_max_bytes=module.PROMPT_INLINE_MAX_BYTES_DEFAULT,
            review_args=[],
            entrypoint="codex-parallel",
        )

        def fake_subprocess_run(
            cmd: list[str],
            *,
            stdout: object | None = None,
            stderr: object | None = None,
            text: bool = False,
            check: bool = False,
            **_: object,
        ) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
            if len(cmd) >= 3 and cmd[0] == sys.executable and cmd[2] == "stateful":
                if "--entrypoint" in cmd:
                    entrypoint = cmd[cmd.index("--entrypoint") + 1]
                    target_state_dir = (
                        readonly_state_dir if entrypoint == "codex-readonly" else agentic_state_dir
                    )
                    return subprocess.CompletedProcess(
                        args=cmd,
                        returncode=0,
                        stdout=(f"{target_state_dir}\n" if text else b""),
                        stderr=("" if text else b""),
                    )
            if cmd[:2] == [real_git, "-C"] and "rev-parse" in cmd:
                output = f"{shared_workspace}\n" if text else f"{shared_workspace}\n".encode("utf-8")
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=0,
                    stdout=output,
                    stderr=("" if text else b""),
                )
            raise AssertionError(f"unexpected subprocess.run call: {cmd}")

        with mock.patch.object(
            module,
            "_prepare_workspace",
            return_value=(
                source_root,
                None,
                None,
                shared_container,
                shared_workspace,
                True,
                False,
            ),
        ), mock.patch.object(
            module.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                args=["child"],
                returncode=1,
                stdout="",
                stderr="boom",
            ),
        ), mock.patch.object(
            module,
            "_cleanup_failed_workspace_setup",
            return_value=None,
        ) as cleanup_failed_workspace_setup_mock, mock.patch.object(
            module,
            "_parallel_agentic_review_policy",
            side_effect=AssertionError(
                "parallel policy should not run before codex-readonly child start succeeds"
            ),
        ), mock.patch.object(
            module,
            "_save_state",
        ):
            with self.assertRaises(module.UserError) as raised:
                module._start_parallel_review(args)

        self.assertIn("codex-readonly child start failed: boom", str(raised.exception))
        cleanup_failed_workspace_setup_mock.assert_called_once_with(
            source_root,
            shared_workspace,
            container_dir=shared_container,
            created_workspace=True,
            cleanup_submodule_worktrees=False,
        )
        self.assertEqual(
            sorted((source_root / ".codex-tmp").glob("isolated-review-parallel-*")),
            [],
        )
        self.assertEqual(
            sorted((source_root / ".codex-tmp").glob("isolated-review-*")),
            [],
        )

    def test_codex_parallel_policy_failure_falls_back_without_aborting_start(self) -> None:
        module = self._load_script_module()
        real_git = module._resolve_real_git()
        source_root = self._create_plain_repo("parallel-policy-failure")
        shared_container = source_root / ".codex-tmp" / "shared-workspace"
        shared_workspace = shared_container / "workspace"
        shared_workspace.mkdir(parents=True)
        state_dir = source_root / ".codex-tmp" / "isolated-review-parallel-test"
        readonly_state_dir = source_root / ".codex-tmp" / "isolated-review-readonly-test"
        agentic_state_dir = source_root / ".codex-tmp" / "isolated-review-agentic-test"
        state_dir.mkdir(parents=True)
        readonly_state_dir.mkdir(parents=True)
        agentic_state_dir.mkdir(parents=True)
        readonly_diff_file = readonly_state_dir / "review.diff"
        readonly_diff_file.write_text("diff --git a/a b/a\n+line\n", encoding="utf-8")
        (readonly_state_dir / "state.json").write_text(
            json.dumps(
                {
                    "source_root": str(source_root),
                    "workspace_root": str(shared_workspace),
                    "reuse_workspace": str(shared_workspace),
                    "diff_file": str(readonly_diff_file),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        args = argparse.Namespace(
            repo=str(source_root),
            base_ref=None,
            head_ref=None,
            lane="custom",
            keep_on_failure=False,
            keep_workspace=False,
            reuse_workspace=None,
            prompt_file=None,
            diff_file=None,
            copy_path=[],
            report_path=None,
            final_reply=None,
            prompt_delivery="auto",
            prompt_inline_max_bytes=module.PROMPT_INLINE_MAX_BYTES_DEFAULT,
            review_args=[],
            entrypoint="codex-parallel",
        )

        def fake_subprocess_run(
            cmd: list[str],
            *,
            stdout: object | None = None,
            stderr: object | None = None,
            text: bool = False,
            check: bool = False,
            **_: object,
        ) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
            if len(cmd) >= 3 and cmd[0] == sys.executable and cmd[2] == "stateful":
                if "--entrypoint" in cmd:
                    entrypoint = cmd[cmd.index("--entrypoint") + 1]
                    target_state_dir = (
                        readonly_state_dir if entrypoint == "codex-readonly" else agentic_state_dir
                    )
                    return subprocess.CompletedProcess(
                        args=cmd,
                        returncode=0,
                        stdout=(f"{target_state_dir}\n" if text else b""),
                        stderr=("" if text else b""),
                    )
            if cmd[:2] == [real_git, "-C"] and "rev-parse" in cmd:
                output = (
                    f"{shared_workspace}\n"
                    if text
                    else f"{shared_workspace}\n".encode("utf-8")
                )
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=0,
                    stdout=output,
                    stderr=("" if text else b""),
                )
            raise AssertionError(f"unexpected subprocess.run call: {cmd}")

        with mock.patch.object(
            module,
            "_prepare_workspace",
            return_value=(
                source_root,
                None,
                None,
                shared_container,
                shared_workspace,
                True,
                False,
            ),
        ), mock.patch.object(
            module.tempfile,
            "mkdtemp",
            side_effect=[
                str(state_dir),
                str(readonly_state_dir),
                str(agentic_state_dir),
            ],
        ), mock.patch.object(
            module.subprocess,
            "run",
            side_effect=fake_subprocess_run,
        ), mock.patch.object(
            module,
            "_resolve_real_git",
            return_value=real_git,
        ), mock.patch.object(
            module,
            "_parallel_agentic_review_policy",
            side_effect=module.UserError("policy boom"),
        ), mock.patch("sys.stdout", new=io.StringIO()):
            result = module._start_parallel_review(args)

        self.assertEqual(result, 0)
        state = json.loads((state_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["child_states"]["readonly"], str(readonly_state_dir))
        self.assertEqual(state["child_states"]["agentic"], str(agentic_state_dir))
        self.assertEqual(state["agentic_policy_error"], "policy boom")
        self.assertNotIn("agentic_start_error", state)

    def test_force_stateful_terminal_exit_records_timeout_exit_code(self) -> None:
        module = self._load_script_module()
        child_state_dir = self.root / "parallel-agentic-child"
        child_state_dir.mkdir()
        child_state = {
            "workspace_root": str(child_state_dir / "workspace"),
            "entrypoint": "codex-review",
            "pid_path": str(child_state_dir / "pid"),
            "exit_code_path": str(child_state_dir / "exit_code"),
            "stdout_path": str(child_state_dir / "stdout.log"),
            "stderr_path": str(child_state_dir / "stderr.log"),
            "lock_path": str(child_state_dir / "runner.lock"),
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (child_state_dir / "pid").write_text("12345\n", encoding="utf-8")

        module._force_stateful_terminal_exit(
            child_state_dir,
            child_state,
            exit_code=module.CODEX_PARALLEL_AGENTIC_TIMEOUT_EXIT_CODE,
            stderr_note="helper terminated the agentic lane",
        )

        self.assertEqual(
            (child_state_dir / "exit_code").read_text(encoding="utf-8").strip(),
            str(module.CODEX_PARALLEL_AGENTIC_TIMEOUT_EXIT_CODE),
        )
        self.assertFalse((child_state_dir / "pid").exists())
        self.assertIn(
            "helper terminated the agentic lane",
            (child_state_dir / "stderr.log").read_text(encoding="utf-8"),
        )

    def test_parallel_agentic_review_policy_scales_with_scope(self) -> None:
        module = self._load_script_module()
        cases = (
            ((100, 3, 30), 0, 20.0 * 60.0, 3.0 * 60.0, 5.0 * 60.0),
            ((5000, 10, 200), 1, 30.0 * 60.0, 5.0 * 60.0, 8.0 * 60.0),
            ((13000, 90, 6000), 2, 45.0 * 60.0, 8.0 * 60.0, 10.0 * 60.0),
            ((26000, 220, 20000), 3, 60.0 * 60.0, 10.0 * 60.0, 15.0 * 60.0),
        )
        for metrics, expected_tier, expected_budget, expected_quiet, expected_lease in cases:
            tracked_files, changed_files, changed_lines = metrics
            with self.subTest(metrics=metrics), mock.patch.object(
                module,
                "_count_tracked_repo_files",
                return_value=tracked_files,
            ), mock.patch.object(
                module,
                "_review_scope_change_metrics",
                return_value=(changed_files, changed_lines),
            ):
                policy = module._parallel_agentic_review_policy(
                    self.repo,
                    base_ref="base",
                    head_ref="head",
                )

            self.assertEqual(policy["tier"], expected_tier)
            self.assertEqual(policy["agentic_timeout_budget_seconds"], expected_budget)
            self.assertEqual(policy["agentic_initial_quiet_seconds"], expected_quiet)
            self.assertEqual(policy["agentic_progress_lease_seconds"], expected_lease)

    def test_review_diff_file_metrics_counts_recursive_live_changes(self) -> None:
        module = self._load_script_module()
        (self.repo / "notes.txt").write_text("root-a\nroot-b\nroot-c\n", encoding="utf-8")
        submodule = self.repo / "deps/sub"
        (submodule / "scratch.txt").write_text(
            "sub-a\nsub-b\nsub-c\nsub-d\n",
            encoding="utf-8",
        )

        diff_path = module._write_generated_uncommitted_review_diff(
            target_root=self.repo,
        )
        changed_files, changed_lines = module._review_diff_file_metrics(diff_path)

        self.assertEqual(changed_files, 5)
        self.assertEqual(changed_lines, 13)

    def test_review_diff_metrics_counts_hunk_lines_starting_with_double_prefix(self) -> None:
        module = self._load_script_module()
        diff_bytes = (
            b"diff --git a/a.txt b/a.txt\n"
            b"--- a/a.txt\n"
            b"+++ b/a.txt\n"
            b"@@ -0,0 +1,3 @@\n"
            b"+++hello\n"
            b"+world\n"
            b"---gone\n"
        )

        changed_files, changed_lines = module._review_diff_metrics_from_bytes(diff_bytes)

        self.assertEqual(changed_files, 1)
        self.assertEqual(changed_lines, 3)

    def test_count_tracked_repo_files_counts_submodule_contents_recursively(self) -> None:
        module = self._load_script_module()
        submodule = self.repo / "deps/sub"
        (submodule / "extra-a.txt").write_text("a\n", encoding="utf-8")
        (submodule / "extra-b.txt").write_text("b\n", encoding="utf-8")
        self.assertEqual(git(submodule, "add", "extra-a.txt", "extra-b.txt").returncode, 0)
        git_commit(submodule, "add extra submodule files")

        tracked_files = module._count_tracked_repo_files(self.repo)

        self.assertEqual(tracked_files, 5)

    def test_parallel_agentic_review_policy_prefers_generated_diff_file_metrics(self) -> None:
        module = self._load_script_module()
        (self.repo / "notes.txt").write_text("root-a\nroot-b\nroot-c\n", encoding="utf-8")
        submodule = self.repo / "deps/sub"
        (submodule / "scratch.txt").write_text(
            "sub-a\nsub-b\nsub-c\nsub-d\n",
            encoding="utf-8",
        )
        diff_path = module._write_generated_uncommitted_review_diff(target_root=self.repo)

        with mock.patch.object(
            module,
            "_count_tracked_repo_files",
            return_value=100,
        ), mock.patch.object(
            module,
            "_review_scope_change_metrics",
            side_effect=AssertionError("policy should use generated diff metrics"),
        ):
            policy = module._parallel_agentic_review_policy(
                self.repo,
                base_ref=None,
                head_ref=None,
                diff_file=diff_path,
            )

        self.assertEqual(policy["changed_files"], 5)
        self.assertEqual(policy["changed_lines"], 13)

    def test_maybe_populate_codex_review_timeout_policy_prefers_workspace_snapshot(self) -> None:
        module = self._load_script_module()
        state_dir = self.root / "stateful-policy-fallback"
        state_dir.mkdir()
        workspace_root = state_dir / "workspace"
        workspace_root.mkdir()
        source_root = self.repo
        state = {
            "workspace_root": str(workspace_root),
            "source_root": str(source_root),
            "base_ref": None,
            "head_ref": None,
            "diff_file": None,
        }
        policy = {
            "agentic_timeout_budget_seconds": 1200.0,
            "agentic_initial_quiet_seconds": 180.0,
            "agentic_progress_lease_seconds": 300.0,
        }

        with mock.patch.object(
            module,
            "_parallel_agentic_review_policy",
            return_value=policy,
        ) as policy_mock:
            module._maybe_populate_codex_review_timeout_policy(state_dir, state)

        policy_mock.assert_called_once_with(
            workspace_root,
            base_ref=None,
            head_ref=None,
            diff_file=None,
        )
        saved_state = json.loads((state_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(saved_state["codex_review_timeout_budget_seconds"], 1200.0)
        self.assertEqual(saved_state["codex_review_initial_quiet_seconds"], 180.0)
        self.assertEqual(saved_state["codex_review_progress_lease_seconds"], 300.0)

    def test_review_scope_change_metrics_uses_frozen_submodule_patch_lines(self) -> None:
        module = self._load_script_module()
        numstat_output = b"1\t1\tdeps/sub\n"
        patch_output = (
            b"Submodule deps/sub 1111111..2222222:\n"
            b"diff --git a/deps/sub/f.txt b/deps/sub/f.txt\n"
            b"--- a/deps/sub/f.txt\n"
            b"+++ b/deps/sub/f.txt\n"
            b"@@ -1,2 +1,4 @@\n"
            b"-a\n"
            b"-b\n"
            b"+c\n"
            b"+d\n"
            b"+e\n"
            b"+f\n"
        )

        with mock.patch.object(
            module,
            "_run",
            side_effect=[
                subprocess.CompletedProcess(
                    args=["git", "diff", "--numstat"],
                    returncode=0,
                    stdout=numstat_output,
                    stderr=b"",
                ),
                subprocess.CompletedProcess(
                    args=["git", "diff", "--submodule=diff"],
                    returncode=0,
                    stdout=patch_output,
                    stderr=b"",
                ),
            ],
        ):
            changed_files, changed_lines = module._review_scope_change_metrics(
                self.repo,
                base_ref="base",
                head_ref="head",
            )

        self.assertEqual(changed_files, 1)
        self.assertEqual(changed_lines, 6)

    def test_parallel_timeout_terminalizes_unknown_agentic_child(self) -> None:
        module = self._load_script_module()
        parent_state_dir = self.root / "parallel-timeout-parent"
        parent_state_dir.mkdir()
        child_state_dir = self.root / "parallel-timeout-child"
        child_state_dir.mkdir()
        child_state = {
            "workspace_root": str(child_state_dir / "workspace"),
            "source_root": str(self.repo),
            "entrypoint": "codex-review",
            "pid_path": str(child_state_dir / "pid"),
            "exit_code_path": str(child_state_dir / "exit_code"),
            "stdout_path": str(child_state_dir / "stdout.log"),
            "stderr_path": str(child_state_dir / "stderr.log"),
            "lock_path": str(child_state_dir / "runner.lock"),
            "runner_spec_path": str(child_state_dir / "runner-spec.json"),
            "started_at": time.time()
            - module.CODEX_PARALLEL_AGENTIC_TIMEOUT_SECONDS
            - 5,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (child_state_dir / "state.json").write_text(
            json.dumps(child_state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (child_state_dir / "runner-spec.json").write_text("{}\n", encoding="utf-8")
        (child_state_dir / "pid").write_text("12345\n", encoding="utf-8")
        parent_state = {
            "state_kind": "parallel",
            "workspace_root": str(parent_state_dir),
            "entrypoint": "codex-parallel",
            "child_states": {
                "agentic": str(child_state_dir),
            },
            "agentic_timed_out": True,
            "agentic_term_sent_at": time.time() - 15,
            "agentic_timeout_budget_seconds": module.CODEX_PARALLEL_AGENTIC_TIMEOUT_SECONDS,
        }

        with mock.patch.object(
            module,
            "_terminate_parallel_runner_process_group",
        ) as terminate_mock:
            module._maybe_enforce_parallel_agentic_timeout(parent_state_dir, parent_state)

        self.assertEqual(
            (child_state_dir / "exit_code").read_text(encoding="utf-8").strip(),
            str(module.CODEX_PARALLEL_AGENTIC_TIMEOUT_EXIT_CODE),
        )
        self.assertIn(
            "total budget",
            (child_state_dir / "stderr.log").read_text(encoding="utf-8"),
        )
        terminate_mock.assert_not_called()

    def test_parallel_timeout_waits_for_recent_agentic_output_within_budget(self) -> None:
        module = self._load_script_module()
        parent_state_dir = self.root / "parallel-budget-parent"
        parent_state_dir.mkdir()
        child_state_dir = self.root / "parallel-budget-child"
        child_state_dir.mkdir()
        stdout_path = child_state_dir / "stdout.log"
        stderr_path = child_state_dir / "stderr.log"
        stdout_path.write_text("progress\n", encoding="utf-8")
        child_state = {
            "workspace_root": str(child_state_dir / "workspace"),
            "source_root": str(self.repo),
            "entrypoint": "codex-review",
            "pid_path": str(child_state_dir / "pid"),
            "exit_code_path": str(child_state_dir / "exit_code"),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "lock_path": str(child_state_dir / "runner.lock"),
            "runner_spec_path": str(child_state_dir / "runner-spec.json"),
            "started_at": 1000.0,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        parent_state = {
            "state_kind": "parallel",
            "workspace_root": str(parent_state_dir),
            "entrypoint": "codex-parallel",
            "child_states": {"agentic": str(child_state_dir)},
            "agentic_timed_out": False,
            "agentic_timeout_budget_seconds": 60.0 * 60.0,
            "agentic_initial_quiet_seconds": 5.0 * 60.0,
            "agentic_progress_lease_seconds": 10.0 * 60.0,
            "agentic_last_output_at": 3500.0,
            "agentic_output_snapshot": module._stateful_output_snapshot(child_state),
        }

        with mock.patch.object(
            module,
            "_parallel_child_state_dir",
            return_value=child_state_dir,
        ), mock.patch.object(
            module,
            "_parallel_child_summary",
            return_value=(
                child_state,
                {
                    "exit_code": None,
                    "running": True,
                    "pid": 12345,
                },
            ),
        ), mock.patch.object(module.time, "time", return_value=3600.0), mock.patch.object(
            module,
            "_terminate_parallel_runner_process_group",
        ) as terminate_mock:
            module._maybe_enforce_parallel_agentic_timeout(parent_state_dir, parent_state)

        self.assertFalse((child_state_dir / "exit_code").exists())
        self.assertFalse(parent_state["agentic_timed_out"])
        terminate_mock.assert_not_called()

    def test_parallel_timeout_uses_initial_quiet_when_logs_are_empty(self) -> None:
        module = self._load_script_module()
        parent_state_dir = self.root / "parallel-empty-parent"
        parent_state_dir.mkdir()
        child_state_dir = self.root / "parallel-empty-child"
        child_state_dir.mkdir()
        stdout_path = child_state_dir / "stdout.log"
        stderr_path = child_state_dir / "stderr.log"
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        child_state = {
            "workspace_root": str(child_state_dir / "workspace"),
            "source_root": str(self.repo),
            "entrypoint": "codex-review",
            "pid_path": str(child_state_dir / "pid"),
            "exit_code_path": str(child_state_dir / "exit_code"),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "lock_path": str(child_state_dir / "runner.lock"),
            "runner_spec_path": str(child_state_dir / "runner-spec.json"),
            "started_at": 1000.0,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        parent_state = {
            "state_kind": "parallel",
            "workspace_root": str(parent_state_dir),
            "entrypoint": "codex-parallel",
            "child_states": {"agentic": str(child_state_dir)},
            "agentic_timed_out": False,
            "agentic_timeout_budget_seconds": 60.0 * 60.0,
            "agentic_initial_quiet_seconds": 5.0 * 60.0,
            "agentic_progress_lease_seconds": 10.0 * 60.0,
            "agentic_last_output_at": None,
            "agentic_output_snapshot": None,
        }

        with mock.patch.object(
            module,
            "_parallel_child_state_dir",
            return_value=child_state_dir,
        ), mock.patch.object(
            module,
            "_parallel_child_summary",
            return_value=(
                child_state,
                {
                    "exit_code": None,
                    "running": False,
                    "pid": None,
                },
            ),
        ), mock.patch.object(module.time, "time", return_value=1305.0), mock.patch.object(
            module,
            "_terminate_parallel_runner_process_group",
        ) as terminate_mock:
            module._maybe_enforce_parallel_agentic_timeout(parent_state_dir, parent_state)

        self.assertEqual(
            (child_state_dir / "exit_code").read_text(encoding="utf-8").strip(),
            str(module.CODEX_PARALLEL_AGENTIC_TIMEOUT_EXIT_CODE),
        )
        self.assertIn(
            "without reviewer output",
            (child_state_dir / "stderr.log").read_text(encoding="utf-8"),
        )
        self.assertIsNone(parent_state["agentic_last_output_at"])
        terminate_mock.assert_not_called()

    def test_parallel_timeout_first_poll_uses_existing_output_mtime(self) -> None:
        module = self._load_script_module()
        parent_state_dir = self.root / "parallel-first-poll-parent"
        parent_state_dir.mkdir()
        child_state_dir = self.root / "parallel-first-poll-child"
        child_state_dir.mkdir()
        stdout_path = child_state_dir / "stdout.log"
        stderr_path = child_state_dir / "stderr.log"
        stdout_path.write_text("progress\n", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        stale_output_at = time.time() - 700.0
        os.utime(stdout_path, (stale_output_at, stale_output_at))
        child_state = {
            "workspace_root": str(child_state_dir / "workspace"),
            "source_root": str(self.repo),
            "entrypoint": "codex-review",
            "pid_path": str(child_state_dir / "pid"),
            "exit_code_path": str(child_state_dir / "exit_code"),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "lock_path": str(child_state_dir / "runner.lock"),
            "runner_spec_path": str(child_state_dir / "runner-spec.json"),
            "started_at": stale_output_at - 300.0,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        parent_state = {
            "state_kind": "parallel",
            "workspace_root": str(parent_state_dir),
            "entrypoint": "codex-parallel",
            "child_states": {"agentic": str(child_state_dir)},
            "agentic_timed_out": False,
            "agentic_timeout_budget_seconds": 60.0 * 60.0,
            "agentic_initial_quiet_seconds": 5.0 * 60.0,
            "agentic_progress_lease_seconds": 10.0 * 60.0,
            "agentic_last_output_at": None,
            "agentic_output_snapshot": None,
        }

        with mock.patch.object(
            module,
            "_parallel_child_state_dir",
            return_value=child_state_dir,
        ), mock.patch.object(
            module,
            "_parallel_child_summary",
            return_value=(
                child_state,
                {
                    "exit_code": None,
                    "running": False,
                    "pid": None,
                },
            ),
        ), mock.patch.object(
            module.time,
            "time",
            return_value=stale_output_at + 700.0,
        ), mock.patch.object(
            module,
            "_terminate_parallel_runner_process_group",
        ) as terminate_mock:
            module._maybe_enforce_parallel_agentic_timeout(parent_state_dir, parent_state)

        self.assertEqual(
            (child_state_dir / "exit_code").read_text(encoding="utf-8").strip(),
            str(module.CODEX_PARALLEL_AGENTIC_TIMEOUT_EXIT_CODE),
        )
        self.assertIn(
            "without new reviewer output",
            (child_state_dir / "stderr.log").read_text(encoding="utf-8"),
        )
        self.assertAlmostEqual(
            float(parent_state["agentic_last_output_at"]),
            stdout_path.stat().st_mtime,
            places=3,
        )
        terminate_mock.assert_not_called()

    def test_parallel_timeout_uses_progress_lease_after_output_stalls(self) -> None:
        module = self._load_script_module()
        parent_state_dir = self.root / "parallel-stall-parent"
        parent_state_dir.mkdir()
        child_state_dir = self.root / "parallel-stall-child"
        child_state_dir.mkdir()
        stdout_path = child_state_dir / "stdout.log"
        stderr_path = child_state_dir / "stderr.log"
        stdout_path.write_text("progress\n", encoding="utf-8")
        stale_output_at = time.time() - 1000.0
        os.utime(stdout_path, (stale_output_at, stale_output_at))
        child_state = {
            "workspace_root": str(child_state_dir / "workspace"),
            "source_root": str(self.repo),
            "entrypoint": "codex-review",
            "pid_path": str(child_state_dir / "pid"),
            "exit_code_path": str(child_state_dir / "exit_code"),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "lock_path": str(child_state_dir / "runner.lock"),
            "runner_spec_path": str(child_state_dir / "runner-spec.json"),
            "started_at": stale_output_at - 1000.0,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        parent_state = {
            "state_kind": "parallel",
            "workspace_root": str(parent_state_dir),
            "entrypoint": "codex-parallel",
            "child_states": {"agentic": str(child_state_dir)},
            "agentic_timed_out": False,
            "agentic_timeout_budget_seconds": 60.0 * 60.0,
            "agentic_initial_quiet_seconds": 5.0 * 60.0,
            "agentic_progress_lease_seconds": 10.0 * 60.0,
            "agentic_last_output_at": stale_output_at,
            "agentic_output_snapshot": module._stateful_output_snapshot(child_state),
        }

        with mock.patch.object(
            module,
            "_parallel_child_state_dir",
            return_value=child_state_dir,
        ), mock.patch.object(
            module,
            "_parallel_child_summary",
            return_value=(
                child_state,
                {
                    "exit_code": None,
                    "running": False,
                    "pid": None,
                },
            ),
        ), mock.patch.object(
            module.time,
            "time",
            return_value=stale_output_at + 805.0,
        ), mock.patch.object(
            module,
            "_terminate_parallel_runner_process_group",
        ) as terminate_mock:
            module._maybe_enforce_parallel_agentic_timeout(parent_state_dir, parent_state)

        self.assertEqual(
            (child_state_dir / "exit_code").read_text(encoding="utf-8").strip(),
            str(module.CODEX_PARALLEL_AGENTIC_TIMEOUT_EXIT_CODE),
        )
        self.assertIn(
            "without new reviewer output",
            (child_state_dir / "stderr.log").read_text(encoding="utf-8"),
        )
        terminate_mock.assert_not_called()

    def test_parallel_summary_waits_for_agentic_lane_when_readonly_failed(self) -> None:
        module = self._load_script_module()
        state_dir = self.root / "parallel-summary-readonly-failed"
        state_dir.mkdir()
        state = {
            "state_kind": "parallel",
            "workspace_root": str(state_dir / "workspace"),
            "entrypoint": "codex-parallel",
            "child_states": {"readonly": "readonly", "agentic": "agentic"},
            "agentic_timed_out": False,
        }

        with mock.patch.object(
            module,
            "_parallel_child_state_dir",
            side_effect=lambda _state, lane_name: pathlib.Path(lane_name),
        ), mock.patch.object(
            module,
            "_parallel_child_summary",
            side_effect=[
                (
                    {},
                    {
                        "status": "failed",
                        "exit_code": 1,
                        "running": False,
                        "stdout_tail": "",
                        "stderr_tail": "readonly failed",
                        "final_available": False,
                    },
                ),
                (
                    {},
                    {
                        "status": "running",
                        "exit_code": None,
                        "running": True,
                        "stdout_tail": "",
                        "stderr_tail": "",
                        "final_available": False,
                    },
                ),
            ],
        ):
            summary = module._parallel_state_summary(state_dir, state)

        self.assertEqual(summary["status"], "running")
        self.assertTrue(summary["running"])
        self.assertIsNone(summary["exit_code"])

    def test_cleanup_worktree_captures_git_remove_output(self) -> None:
        module = self._load_script_module()
        source_root = self.root / "cleanup-source"
        source_root.mkdir()
        workspace_root = self.root / "cleanup-workspace"
        workspace_root.mkdir()

        with mock.patch.object(module, "_run") as run_mock:
            module._cleanup_worktree(
                source_root,
                workspace_root,
                cleanup_submodule_worktrees=False,
                preserve_container_dir=True,
            )

        run_mock.assert_called_once_with(
            [
                module._resolve_real_git(),
                "-C",
                str(source_root),
                "worktree",
                "remove",
                "--force",
                str(workspace_root),
            ],
            capture_output=True,
        )

    def test_parallel_final_reports_agentic_start_error_as_inconclusive(self) -> None:
        module = self._load_script_module()
        state_dir = self.root / "parallel-final-start-error"
        state_dir.mkdir()
        report = module._read_parallel_final_text(
            state_dir,
            {
                "state_kind": "parallel",
                "workspace_root": str(state_dir),
                "entrypoint": "codex-parallel",
                "child_states": {},
                "agentic_start_error": "agentic lane failed before launch",
            },
        )

        self.assertIn("## Agentic", report)
        self.assertIn("Inconclusive: agentic lane failed before launch", report)
        self.assertNotIn("Lane is still running.", report)

    def test_parallel_summary_treats_agentic_start_error_as_terminal_advisory(self) -> None:
        module = self._load_script_module()
        state_dir = self.root / "parallel-summary-start-error"
        state_dir.mkdir()
        state = {
            "state_kind": "parallel",
            "workspace_root": str(state_dir / "workspace"),
            "entrypoint": "codex-parallel",
            "child_states": {"readonly": "readonly"},
            "agentic_start_error": "agentic lane failed before launch",
            "agentic_timed_out": False,
        }

        with mock.patch.object(
            module,
            "_parallel_child_state_dir",
            side_effect=lambda _state, lane_name: (
                pathlib.Path("readonly") if lane_name == "readonly" else None
            ),
        ), mock.patch.object(
            module,
            "_parallel_child_summary",
            return_value=(
                {},
                {
                    "status": "passed",
                    "exit_code": 0,
                    "running": False,
                    "stdout_tail": "",
                    "stderr_tail": "",
                    "final_available": True,
                },
            ),
        ):
            summary = module._parallel_state_summary(state_dir, state)

        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["exit_code"], 0)
        self.assertEqual(summary["children"]["agentic"]["status"], "inconclusive")
        self.assertEqual(summary["children"]["agentic"]["exit_code"], 1)
        self.assertIn(
            "agentic lane failed before launch",
            summary["children"]["agentic"]["stderr_tail"],
        )

    def test_parallel_final_ignores_failed_lane_final_text(self) -> None:
        module = self._load_script_module()
        report = module._format_parallel_child_result(
            label="Agentic",
            summary={
                "exit_code": 124,
                "stderr_tail": "helper terminated the agentic lane after 1200s total budget",
                "stdout_tail": "raw stdout tail",
            },
            final_text="Agentic findings.\n",
            advisory=True,
        )

        self.assertIn("Inconclusive: helper terminated the agentic lane after 1200s total budget", report)
        self.assertNotIn("Agentic findings.", report)

    def test_parallel_final_does_not_render_success_without_final_as_failure(self) -> None:
        module = self._load_script_module()
        report = module._format_parallel_child_result(
            label="Readonly",
            summary={
                "exit_code": 0,
                "stderr_tail": "",
                "stdout_tail": "",
            },
            final_text=None,
            advisory=False,
        )

        self.assertIn("Completed, but no final reviewer message was available.", report)
        self.assertNotIn("Failed:", report)

    def test_parallel_final_renders_unknown_lane_as_inconclusive(self) -> None:
        module = self._load_script_module()
        report = module._format_parallel_child_result(
            label="Agentic",
            summary={
                "exit_code": None,
                "status": "unknown",
                "stderr_tail": "",
                "stdout_tail": "",
            },
            final_text=None,
            advisory=True,
        )

        self.assertIn("Inconclusive: lane ended without a terminal exit code", report)

    def test_parallel_summary_propagates_unknown_primary_lane(self) -> None:
        module = self._load_script_module()
        state_dir = self.root / "parallel-summary-unknown"
        state_dir.mkdir()
        state = {
            "state_kind": "parallel",
            "workspace_root": str(state_dir / "workspace"),
            "entrypoint": "codex-parallel",
            "child_states": {"readonly": "readonly", "agentic": "agentic"},
            "agentic_timed_out": False,
        }

        with mock.patch.object(
            module,
            "_parallel_child_state_dir",
            side_effect=lambda _state, lane_name: pathlib.Path(lane_name),
        ), mock.patch.object(
            module,
            "_parallel_child_summary",
            side_effect=[
                (
                    {},
                    {
                        "status": "unknown",
                        "exit_code": None,
                        "running": False,
                        "stdout_tail": "",
                        "stderr_tail": "",
                        "final_available": False,
                    },
                ),
                (
                    {},
                    {
                        "status": "failed",
                        "exit_code": 124,
                        "running": False,
                        "stdout_tail": "",
                        "stderr_tail": "timed out",
                        "final_available": False,
                    },
                ),
            ],
        ):
            summary = module._parallel_state_summary(state_dir, state)

        self.assertEqual(summary["status"], "unknown")
        self.assertIsNone(summary["exit_code"])

    def test_parallel_summary_keeps_unknown_agentic_lane_running(self) -> None:
        module = self._load_script_module()
        state_dir = self.root / "parallel-summary-advisory"
        state_dir.mkdir()
        state = {
            "state_kind": "parallel",
            "workspace_root": str(state_dir / "workspace"),
            "entrypoint": "codex-parallel",
            "child_states": {"readonly": "readonly", "agentic": "agentic"},
            "agentic_timed_out": False,
        }

        with mock.patch.object(
            module,
            "_parallel_child_state_dir",
            side_effect=lambda _state, lane_name: pathlib.Path(lane_name),
        ), mock.patch.object(
            module,
            "_parallel_child_summary",
            side_effect=[
                (
                    {},
                    {
                        "status": "passed",
                        "exit_code": 0,
                        "running": False,
                        "stdout_tail": "",
                        "stderr_tail": "",
                        "final_available": True,
                    },
                ),
                (
                    {},
                    {
                        "status": "unknown",
                        "exit_code": None,
                        "running": False,
                        "stdout_tail": "",
                        "stderr_tail": "",
                        "final_available": False,
                    },
                ),
            ],
        ):
            summary = module._parallel_state_summary(state_dir, state)

        self.assertEqual(summary["status"], "running")
        self.assertTrue(summary["running"])
        self.assertIsNone(summary["exit_code"])

    def test_parallel_child_state_dir_rejects_path_outside_source_tmp(self) -> None:
        module = self._load_script_module()
        source_root = self._create_plain_repo("parallel-child-state-path")
        allowed_state_dir = source_root / ".codex-tmp" / "isolated-review-child"
        poisoned_state_dir = self.root / "outside-child-state"

        resolved_allowed = module._parallel_child_state_dir(
            {
                "source_root": str(source_root),
                "child_states": {"readonly": str(allowed_state_dir)},
            },
            "readonly",
        )
        self.assertEqual(
            resolved_allowed,
            allowed_state_dir.resolve(strict=False),
        )

        with self.assertRaisesRegex(
            module.UserError,
            "parallel child state_dir must live under the source repo's .codex-tmp directory",
        ):
            module._parallel_child_state_dir(
                {
                    "source_root": str(source_root),
                    "child_states": {"readonly": str(poisoned_state_dir)},
                },
                "readonly",
            )

    def test_refresh_parallel_state_propagates_settle_timeout_to_readonly_child(self) -> None:
        module = self._load_script_module()
        state_dir = self.root / "parallel-refresh-readonly"
        state_dir.mkdir()
        state = {
            "state_kind": "parallel",
            "workspace_root": str(self.repo / ".codex-tmp" / "parallel-refresh-workspace"),
            "entrypoint": "codex-parallel",
            "source_root": str(self.repo),
            "child_states": {"readonly": "readonly-state"},
        }
        readonly_state_dir = state_dir / "readonly-state"

        with mock.patch.object(
            module,
            "_load_state",
            side_effect=[dict(state), dict(state), dict(state)],
        ), mock.patch.object(
            module,
            "_parallel_child_state_dir",
            side_effect=lambda _state, lane_name: (
                readonly_state_dir if lane_name == "readonly" else None
            ),
        ), mock.patch.object(
            module,
            "_refresh_state",
            return_value={"entrypoint": "codex-readonly"},
        ) as refresh_mock, mock.patch.object(
            module,
            "_maybe_enforce_parallel_agentic_timeout",
        ) as agentic_timeout_mock, mock.patch.object(
            module,
            "_maybe_abort_parallel_agentic_after_primary_failure",
        ) as abort_mock:
            refreshed = module._refresh_parallel_state(state_dir, settle_timeout=True)

        refresh_mock.assert_called_once_with(readonly_state_dir, settle_timeout=True)
        agentic_timeout_mock.assert_called_once()
        abort_mock.assert_called_once()
        self.assertEqual(refreshed["entrypoint"], "codex-parallel")

    def test_materialize_path_uses_bulk_copy_when_directory_has_no_exclusions(self) -> None:
        module = self._load_script_module()
        source_root = self.root / "materialize-bulk-source"
        source_dir = source_root / "src"
        source_dir.mkdir(parents=True)
        (source_dir / "file.txt").write_text("bulk\n", encoding="utf-8")
        target_dir = self.root / "materialize-bulk-target"

        with mock.patch.object(module, "_copy_dir_contents") as copy_dir_contents_mock, mock.patch.object(
            module,
            "_materialize_directory_contents",
        ) as materialize_directory_contents_mock:
            module._materialize_path(
                source_dir,
                target_dir,
                source_root=source_root,
                excluded_paths=[],
            )

        copy_dir_contents_mock.assert_called_once_with(source_dir, target_dir)
        materialize_directory_contents_mock.assert_not_called()

    def test_parallel_cleanup_requests_shared_container_removal(self) -> None:
        module = self._load_script_module()
        source_root = self._create_plain_repo("parallel-cleanup-source")
        shared_container = source_root / ".codex-tmp" / "isolated-review-shared"
        workspace_root = shared_container / "workspace"
        workspace_root.mkdir(parents=True)
        state_dir = self.root / "parallel-cleanup-state"
        state_dir.mkdir()
        state = {
            "state_kind": "parallel",
            "workspace_root": str(workspace_root),
            "source_root": str(source_root),
            "entrypoint": "codex-parallel",
            "cleanup_submodule_worktrees": False,
            "keep_workspace": False,
            "keep_on_failure": False,
            "workspace_cleaned": False,
        }

        with mock.patch.object(module, "_source_root_recognizes_workspace", return_value=True), mock.patch.object(
            module,
            "_cleanup_worktree",
        ) as cleanup_worktree_mock:
            module._maybe_cleanup_parallel_workspace(
                state_dir,
                state,
                exit_code=0,
            )

        cleanup_worktree_mock.assert_called_once_with(
            source_root,
            workspace_root,
            cleanup_submodule_worktrees=False,
            preserve_container_dir=False,
        )
        self.assertTrue(state["workspace_cleaned"])

    def test_codex_review_rejects_frozen_prompt_contract_flags(self) -> None:
        repo, base, head = self._create_review_range_repo("codex-range-prompt-contracts")
        range_diff = repo / ".codex-tmp" / "range.diff"
        range_diff.write_text("diff --git a/root.txt b/root.txt\n", encoding="utf-8")
        cases = (
            (
                ["--prompt-file", str(repo / ".codex-tmp" / "range.prompt")],
                "--prompt-file",
            ),
            (["--diff-file", str(range_diff)], "--diff-file"),
            (["--final-reply", "DONE"], "--final-reply"),
        )
        for extra_args, expected_flag in cases:
            with self.subTest(flag=expected_flag):
                failed = run(
                    [
                        sys.executable,
                        str(SCRIPT_PATH),
                        "stateful",
                        "start",
                        "--repo",
                        str(repo),
                        "--entrypoint",
                        "codex-review",
                        "--base-ref",
                        base,
                        "--head-ref",
                        head,
                        *extra_args,
                    ],
                    env=self._base_env(),
                )
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn(
                    "frozen codex-review cannot honor helper-managed prompt contracts",
                    failed.stderr,
                )
                self.assertIn(expected_flag, failed.stderr)

    def test_codex_review_rejects_report_path_for_all_review_modes(self) -> None:
        repo, base, head = self._create_review_range_repo("codex-range-report-path")
        cases = (
            ([], "stateful", "start"),
            (["--base-ref", base, "--head-ref", head], "stateful", "start"),
        )
        for extra_args, command, action in cases:
            with self.subTest(extra_args=extra_args):
                failed = run(
                    [
                        sys.executable,
                        str(SCRIPT_PATH),
                        command,
                        action,
                        "--repo",
                        str(repo),
                        "--entrypoint",
                        "codex-review",
                        "--report-path",
                        ".codex-tmp/reports/final.md",
                        *extra_args,
                    ],
                    env=self._base_env(),
                )
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn(
                    "codex-review cannot honor helper-managed `--report-path`",
                    failed.stderr,
                )

    def test_codex_review_rejects_uncommitted_prompt_contract_flags(self) -> None:
        cases = (
            (["--prompt-file", str(self.repo / ".codex-tmp" / "review.prompt")], "--prompt-file"),
            (["--diff-file", str(self.repo / ".codex-tmp" / "review.diff")], "--diff-file"),
            (["--final-reply", "DONE"], "--final-reply"),
            (["--prompt-delivery", "inline"], "--prompt-delivery"),
            (["--prompt-inline-max-bytes", "1"], "--prompt-inline-max-bytes"),
        )
        for extra_args, expected_flag in cases:
            with self.subTest(flag=expected_flag):
                failed = run(
                    [
                        sys.executable,
                        str(SCRIPT_PATH),
                        "stateful",
                        "start",
                        "--repo",
                        str(self.repo),
                        "--entrypoint",
                        "codex-review",
                        *extra_args,
                    ],
                    env=self._base_env(),
                )
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn(
                    "uncommitted codex-review cannot honor helper-managed prompt contracts",
                    failed.stderr,
                )
                self.assertIn(expected_flag, failed.stderr)

    def test_codex_review_prepare_only_rejects_report_path(self) -> None:
        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "codex-review",
                "--prepare-only",
                "--report-path",
                ".codex-tmp/reports/final.md",
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(
            "codex-review cannot honor helper-managed `--report-path`",
            failed.stderr,
        )
        leaked_workspaces = sorted((self.repo / ".codex-tmp").glob("isolated-review-*"))
        self.assertEqual(leaked_workspaces, [])

    def test_codex_review_prepare_only_rejects_explicit_prompt_without_leaking_workspace(
        self,
    ) -> None:
        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "codex-review",
                "--prepare-only",
                "--",
                "Explicit reviewer prompt",
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(
            "codex-review cannot combine an explicit prompt with `--uncommitted`",
            failed.stderr,
        )
        leaked_workspaces = sorted((self.repo / ".codex-tmp").glob("isolated-review-*"))
        self.assertEqual(leaked_workspaces, [])

    def test_codex_review_reuse_workspace_rejects_report_path_without_mutation(self) -> None:
        prepare = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--prepare-only",
            ],
            env=self._base_env(),
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        workspace_root = pathlib.Path(
            [line.strip() for line in prepare.stdout.splitlines() if line.strip()][-1]
        )

        report_dir = workspace_root / ".codex-tmp" / "reports"
        prompt_copy = workspace_root / ".codex-tmp" / "review.prompt"
        diff_copy = workspace_root / ".codex-tmp" / "review.diff"
        self.assertFalse(report_dir.exists())
        self.assertFalse(prompt_copy.exists())
        self.assertFalse(diff_copy.exists())

        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(self.repo),
                "--reuse-workspace",
                str(workspace_root),
                "--entrypoint",
                "codex-review",
                "--prompt-file",
                str(self.repo / ".codex-tmp" / "review.prompt"),
                "--diff-file",
                str(self.repo / ".codex-tmp" / "review.diff"),
                "--report-path",
                ".codex-tmp/reports/final.md",
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(
            "codex-review cannot honor helper-managed `--report-path`",
            failed.stderr,
        )
        self.assertFalse(report_dir.exists())
        self.assertFalse(prompt_copy.exists())
        self.assertFalse(diff_copy.exists())

    def test_codex_review_reuse_workspace_rejects_frozen_explicit_prompt_without_mutation(
        self,
    ) -> None:
        range_repo, base_commit, head_commit = self._create_review_range_repo(
            "codex-review-frozen-explicit-prompt-reuse"
        )
        prepare = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(range_repo),
                "--prepare-only",
            ],
            env=self._base_env(),
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        workspace_root = pathlib.Path(
            [line.strip() for line in prepare.stdout.splitlines() if line.strip()][-1]
        )

        diff_copy = workspace_root / ".codex-tmp" / "review.diff"
        runtime_temp_dir = workspace_root / ".codex-tmp" / "codex-review-tmp"
        self.assertFalse(diff_copy.exists())
        self.assertFalse(runtime_temp_dir.exists())

        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(range_repo),
                "--reuse-workspace",
                str(workspace_root),
                "--entrypoint",
                "codex-review",
                "--base-ref",
                base_commit,
                "--head-ref",
                head_commit,
                "--",
                "Explicit reviewer prompt",
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(
            "codex-review cannot combine an explicit prompt with helper-managed `--base`",
            failed.stderr,
        )
        self.assertFalse(diff_copy.exists())
        self.assertFalse(runtime_temp_dir.exists())

    def test_run_prepared_review_returns_failure_when_cleanup_breaks_after_success(self) -> None:
        module = self._load_script_module()
        workspace_root = self.root / "run-prepared-workspace"
        workspace_root.mkdir()
        args = argparse.Namespace(verbose=False, prepare_only=False)
        cleanup_mock = mock.Mock(return_value=module.UserError("cleanup failed"))
        prepared = {
            "args": args,
            "workspace_root": workspace_root,
            "command": ["true"],
            "child_env": {},
            "stdin_bytes": None,
            "placeholders": {"{review_range}": None},
        }
        stderr = io.StringIO()
        with (
            mock.patch.object(
                module.subprocess,
                "run",
                return_value=mock.Mock(returncode=0),
            ),
            mock.patch.dict(
                module._run_prepared_review.__globals__,
                {"_cleanup_prepared_workspace": cleanup_mock},
            ),
            mock.patch.object(sys, "stderr", stderr),
        ):
            exit_code = module._run_prepared_review(prepared)
        cleanup_mock.assert_called_once()
        self.assertEqual(exit_code, 1)
        self.assertIn("cleanup failed", stderr.getvalue())

    def test_codex_review_runner_spec_omits_inherited_environment(self) -> None:
        env = self._base_env()
        env["INHERITED_SECRET_TOKEN"] = "top-secret"
        env["OPENAI_API_KEY"] = "provider-token"
        env["HTTPS_PROXY"] = "https://proxy.example.test:8443"
        env["REQUESTS_CA_BUNDLE"] = "/tmp/fake-certs.pem"
        env["CODEX_CI"] = "1"
        env["CODEX_HOME"] = "/tmp/fake-codex-home"
        env["CODEX_INTERNAL_ORIGINATOR_OVERRIDE"] = "Codex Desktop"
        env["CODEX_SANDBOX_NETWORK_DISABLED"] = "1"
        env["CODEX_THREAD_ID"] = "thread-leak"
        start = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(self.repo),
                "--entrypoint",
                "codex-review",
            ],
            env=env,
        )
        self.assertEqual(start.returncode, 0, start.stderr)
        state_dir = pathlib.Path(start.stdout.strip().splitlines()[-1])

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)
        runner_spec = json.loads((state_dir / "runner-spec.json").read_text(encoding="utf-8"))
        self.assertNotIn("env", runner_spec)
        self.assertNotIn("INHERITED_SECRET_TOKEN", runner_spec["env_overrides"])
        self.assertIn("PATH", runner_spec["env_overrides"])
        stdout_lines = (state_dir / "stdout.log").read_text(encoding="utf-8").splitlines()
        payload = json.loads(stdout_lines[-1])["payload"]
        self.assertEqual(payload["codex_ci"], "1")
        self.assertEqual(payload["codex_home"], "/tmp/fake-codex-home")
        self.assertEqual(
            payload["codex_internal_originator_override"],
            "Codex Desktop",
        )
        self.assertEqual(payload["codex_sandbox_network_disabled"], "1")
        self.assertIsNone(payload["codex_shell"])
        self.assertIsNone(payload["codex_thread_id"])
        self.assertIsNone(payload["inherited_secret_token"])
        self.assertEqual(payload["openai_api_key"], "provider-token")
        self.assertEqual(payload["https_proxy"], "https://proxy.example.test:8443")
        self.assertEqual(payload["requests_ca_bundle"], "/tmp/fake-certs.pem")

    def test_resolve_real_codex_searches_directory_entries_from_defpath(self) -> None:
        module = self._load_script_module()
        defpath_bin = self.root / "defpath-bin"
        defpath_bin.mkdir()
        shutil.copy2(self.fake_bin / "codex", defpath_bin / "codex")
        (defpath_bin / "codex").chmod(0o755)

        original_defpath = os.defpath
        original_override = os.environ.pop("CODEX_REAL_CODEX", None)
        original_fake_override = os.environ.pop("FAKE_CODEX_PATH", None)
        original_preferred = module.PREFERRED_CODEX_PATHS
        original_trusted_entries = module.TRUSTED_CHILD_PATH_ENTRIES
        try:
            os.defpath = str(defpath_bin)
            module.os.defpath = str(defpath_bin)
            module.PREFERRED_CODEX_PATHS = ()
            module.TRUSTED_CHILD_PATH_ENTRIES = ()
            resolved = module._resolve_real_codex()
        finally:
            module.PREFERRED_CODEX_PATHS = original_preferred
            module.TRUSTED_CHILD_PATH_ENTRIES = original_trusted_entries
            os.defpath = original_defpath
            module.os.defpath = original_defpath
            if original_override is not None:
                os.environ["CODEX_REAL_CODEX"] = original_override
            if original_fake_override is not None:
                os.environ["FAKE_CODEX_PATH"] = original_fake_override

        self.assertEqual(
            pathlib.Path(resolved).resolve(),
            (defpath_bin / "codex").resolve(),
        )

    def test_resolve_real_codex_ignores_untrusted_override(self) -> None:
        module = self._load_script_module()
        trusted_bin = self.root / "trusted-bin"
        trusted_bin.mkdir()
        shutil.copy2(self.fake_bin / "codex", trusted_bin / "codex")
        (trusted_bin / "codex").chmod(0o755)

        original_defpath = os.defpath
        original_override = os.environ.get("CODEX_REAL_CODEX")
        original_fake_override = os.environ.pop("FAKE_CODEX_PATH", None)
        original_preferred = module.PREFERRED_CODEX_PATHS
        original_trusted_entries = module.TRUSTED_CHILD_PATH_ENTRIES
        try:
            os.defpath = str(trusted_bin)
            module.os.defpath = str(trusted_bin)
            os.environ["CODEX_REAL_CODEX"] = str((self.fake_bin / "codex").resolve())
            module.PREFERRED_CODEX_PATHS = ()
            module.TRUSTED_CHILD_PATH_ENTRIES = (str(trusted_bin),)
            resolved = module._resolve_real_codex()
        finally:
            module.PREFERRED_CODEX_PATHS = original_preferred
            module.TRUSTED_CHILD_PATH_ENTRIES = original_trusted_entries
            os.defpath = original_defpath
            module.os.defpath = original_defpath
            if original_override is None:
                os.environ.pop("CODEX_REAL_CODEX", None)
            else:
                os.environ["CODEX_REAL_CODEX"] = original_override
            if original_fake_override is not None:
                os.environ["FAKE_CODEX_PATH"] = original_fake_override

        self.assertEqual(
            pathlib.Path(resolved).resolve(),
            (trusted_bin / "codex").resolve(),
        )

    def test_resolve_real_codex_ignores_non_codex_override_name(self) -> None:
        module = self._load_script_module()
        trusted_bin = self.root / "trusted-bin-non-codex"
        trusted_bin.mkdir()
        shutil.copy2(self.fake_bin / "codex", trusted_bin / "codex")
        (trusted_bin / "codex").chmod(0o755)
        bad_override = trusted_bin / "python3"
        shutil.copy2(self.fake_bin / "codex", bad_override)
        bad_override.chmod(0o755)

        original_defpath = os.defpath
        original_override = os.environ.get("CODEX_REAL_CODEX")
        original_fake_override = os.environ.pop("FAKE_CODEX_PATH", None)
        original_preferred = module.PREFERRED_CODEX_PATHS
        original_trusted_entries = module.TRUSTED_CHILD_PATH_ENTRIES
        try:
            os.defpath = str(trusted_bin)
            module.os.defpath = str(trusted_bin)
            os.environ["CODEX_REAL_CODEX"] = str(bad_override.resolve())
            module.PREFERRED_CODEX_PATHS = ()
            module.TRUSTED_CHILD_PATH_ENTRIES = (str(trusted_bin),)
            resolved = module._resolve_real_codex()
        finally:
            module.PREFERRED_CODEX_PATHS = original_preferred
            module.TRUSTED_CHILD_PATH_ENTRIES = original_trusted_entries
            os.defpath = original_defpath
            module.os.defpath = original_defpath
            if original_override is None:
                os.environ.pop("CODEX_REAL_CODEX", None)
            else:
                os.environ["CODEX_REAL_CODEX"] = original_override
            if original_fake_override is not None:
                os.environ["FAKE_CODEX_PATH"] = original_fake_override

        self.assertEqual(
            pathlib.Path(resolved).resolve(),
            (trusted_bin / "codex").resolve(),
        )

    def test_resolve_real_codex_rejects_trusted_symlink_to_non_codex_binary(self) -> None:
        module = self._load_script_module()
        trusted_bin = self.root / "trusted-bin-symlink"
        trusted_bin.mkdir()
        os.symlink(shutil.which("echo") or "/bin/echo", trusted_bin / "codex")

        original_defpath = os.defpath
        original_override = os.environ.pop("CODEX_REAL_CODEX", None)
        original_fake_override = os.environ.pop("FAKE_CODEX_PATH", None)
        original_preferred = module.PREFERRED_CODEX_PATHS
        original_trusted_entries = module.TRUSTED_CHILD_PATH_ENTRIES
        try:
            os.defpath = str(trusted_bin)
            module.os.defpath = str(trusted_bin)
            module.PREFERRED_CODEX_PATHS = ()
            module.TRUSTED_CHILD_PATH_ENTRIES = (str(trusted_bin),)
            with self.assertRaises(module.UserError):
                module._resolve_real_codex()
        finally:
            module.PREFERRED_CODEX_PATHS = original_preferred
            module.TRUSTED_CHILD_PATH_ENTRIES = original_trusted_entries
            os.defpath = original_defpath
            module.os.defpath = original_defpath
            if original_override is not None:
                os.environ["CODEX_REAL_CODEX"] = original_override
            if original_fake_override is not None:
                os.environ["FAKE_CODEX_PATH"] = original_fake_override

    def test_resolve_real_codex_ignores_fake_override_without_test_opt_in(self) -> None:
        module = self._load_script_module()
        trusted_bin = self.root / "trusted-bin-no-fake"
        trusted_bin.mkdir()
        shutil.copy2(self.fake_bin / "codex", trusted_bin / "codex")
        (trusted_bin / "codex").chmod(0o755)

        original_defpath = os.defpath
        original_fake_override = os.environ.get("FAKE_CODEX_PATH")
        original_fake_toggle = os.environ.pop("ISOLATED_EXTERNAL_REVIEW_TEST_FAKE_CODEX", None)
        original_override = os.environ.pop("CODEX_REAL_CODEX", None)
        original_preferred = module.PREFERRED_CODEX_PATHS
        original_trusted_entries = module.TRUSTED_CHILD_PATH_ENTRIES
        try:
            os.defpath = str(trusted_bin)
            module.os.defpath = str(trusted_bin)
            os.environ["FAKE_CODEX_PATH"] = str((self.fake_bin / "codex").resolve())
            module.PREFERRED_CODEX_PATHS = ()
            module.TRUSTED_CHILD_PATH_ENTRIES = ()
            resolved = module._resolve_real_codex()
        finally:
            module.PREFERRED_CODEX_PATHS = original_preferred
            module.TRUSTED_CHILD_PATH_ENTRIES = original_trusted_entries
            os.defpath = original_defpath
            module.os.defpath = original_defpath
            if original_fake_override is None:
                os.environ.pop("FAKE_CODEX_PATH", None)
            else:
                os.environ["FAKE_CODEX_PATH"] = original_fake_override
            if original_fake_toggle is not None:
                os.environ["ISOLATED_EXTERNAL_REVIEW_TEST_FAKE_CODEX"] = original_fake_toggle
            if original_override is not None:
                os.environ["CODEX_REAL_CODEX"] = original_override

        self.assertEqual(
            pathlib.Path(resolved).resolve(),
            (trusted_bin / "codex").resolve(),
        )

    def test_resolve_codex_review_linux_sandbox_flags_uses_legacy_landlock(self) -> None:
        module = self._load_script_module()
        module._resolve_codex_review_linux_sandbox_flags.cache_clear()
        default_probe = subprocess.CompletedProcess(
            args=["codex", "sandbox", "linux"],
            returncode=1,
            stdout=b"",
            stderr=(
                b"bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted\n"
            ),
        )
        legacy_probe = subprocess.CompletedProcess(
            args=["codex", "sandbox", "linux"],
            returncode=0,
            stdout=b"",
            stderr=b"",
        )
        with mock.patch.object(module.sys, "platform", "linux"), mock.patch.object(
            module,
            "_probe_codex_linux_sandbox",
            side_effect=[default_probe, legacy_probe],
        ):
            flags = module._resolve_codex_review_linux_sandbox_flags("/fake/codex")
        self.assertEqual(flags, module.CODEX_REVIEW_LINUX_LEGACY_LANDLOCK_FLAGS)

    def test_resolve_codex_review_linux_sandbox_flags_raises_when_legacy_retry_fails(
        self,
    ) -> None:
        module = self._load_script_module()
        module._resolve_codex_review_linux_sandbox_flags.cache_clear()
        default_probe = subprocess.CompletedProcess(
            args=["codex", "sandbox", "linux"],
            returncode=1,
            stdout=b"",
            stderr=(
                b"bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted\n"
            ),
        )
        legacy_probe = subprocess.CompletedProcess(
            args=["codex", "sandbox", "linux"],
            returncode=1,
            stdout=b"",
            stderr=b"legacy landlock probe failed\n",
        )
        with mock.patch.object(module.sys, "platform", "linux"), mock.patch.object(
            module,
            "_probe_codex_linux_sandbox",
            side_effect=[default_probe, legacy_probe],
        ):
            with self.assertRaises(module.UserError) as raised:
                module._resolve_codex_review_linux_sandbox_flags("/fake/codex-fail")
        self.assertIn("legacy landlock retry also failed", str(raised.exception))
        self.assertIn("default probe stderr", str(raised.exception))
        self.assertIn("legacy landlock probe stderr", str(raised.exception))

    def test_probe_codex_linux_sandbox_times_out(self) -> None:
        module = self._load_script_module()
        with mock.patch.object(
            module,
            "_resolve_trusted_true_path",
            return_value="/usr/bin/true",
        ), mock.patch.object(module.subprocess, "run") as run_mock:
            run_mock.side_effect = subprocess.TimeoutExpired(
                cmd=["/fake/codex", "sandbox", "linux", "/usr/bin/true"],
                timeout=module.CODEX_REVIEW_LINUX_SANDBOX_PROBE_TIMEOUT_SECONDS,
            )
            with self.assertRaises(module.UserError) as raised:
                module._probe_codex_linux_sandbox(codex_path="/fake/codex")
        self.assertEqual(
            run_mock.call_args.kwargs["timeout"],
            module.CODEX_REVIEW_LINUX_SANDBOX_PROBE_TIMEOUT_SECONDS,
        )
        self.assertIn("timed out after", str(raised.exception))
        self.assertIn("/fake/codex", str(raised.exception))

    def test_probe_codex_linux_sandbox_wraps_oserror(self) -> None:
        module = self._load_script_module()
        with mock.patch.object(
            module,
            "_resolve_trusted_true_path",
            return_value="/usr/bin/true",
        ), mock.patch.object(module.subprocess, "run", side_effect=OSError("boom")):
            with self.assertRaises(module.UserError) as raised:
                module._probe_codex_linux_sandbox(
                    codex_path="/fake/codex",
                    extra_args=module.CODEX_REVIEW_LINUX_LEGACY_LANDLOCK_FLAGS,
                )
        self.assertIn("failed to probe Linux Codex sandbox", str(raised.exception))
        self.assertIn("/fake/codex", str(raised.exception))
        self.assertIn("use_legacy_landlock", str(raised.exception))

    def test_apply_codex_review_defaults_injects_linux_landlock_flags(self) -> None:
        module = self._load_script_module()
        runtime_temp_dir = self.root / "codex-review-tmp-linux"
        final_path = self.root / "codex-review-final-linux.txt"
        with mock.patch.object(
            module,
            "_resolve_codex_review_linux_sandbox_flags",
            return_value=module.CODEX_REVIEW_LINUX_LEGACY_LANDLOCK_FLAGS,
        ):
            command, prompt_delivery, stdin_bytes, resolved_final_path = (
                module._apply_codex_review_defaults(
                    codex_path="/fake/codex",
                    rendered_args=[],
                    workspace_root=self.repo,
                    final_path=final_path,
                    runtime_temp_dir=runtime_temp_dir,
                    base_ref=None,
                    prompt_text=None,
                )
            )
        self.assertEqual(
            command[: len(module.CODEX_REVIEW_LINUX_LEGACY_LANDLOCK_FLAGS)],
            list(module.CODEX_REVIEW_LINUX_LEGACY_LANDLOCK_FLAGS),
        )
        self.assertEqual(
            command[
                len(module.CODEX_REVIEW_LINUX_LEGACY_LANDLOCK_FLAGS) : len(
                    module.CODEX_REVIEW_LINUX_LEGACY_LANDLOCK_FLAGS
                )
                + 4
            ],
            ["-s", "read-only", "--add-dir", str(runtime_temp_dir)],
        )
        self.assertEqual(prompt_delivery, "builtin-review")
        self.assertIsNone(stdin_bytes)
        self.assertEqual(resolved_final_path.resolve(), final_path.resolve())

    def test_apply_codex_readonly_defaults_injects_linux_landlock_flags(self) -> None:
        module = self._load_script_module()
        runtime_temp_dir = self.root / "codex-readonly-tmp-linux"
        final_path = self.root / "codex-readonly-final-linux.txt"
        placeholders = {
            "{workspace}": str(self.repo),
            "{source_repo}": str(self.repo),
            "{diff_file}": str(self.repo / ".codex-tmp" / "review.diff"),
            "{review_range}": "base..head",
        }
        with mock.patch.object(
            module,
            "_resolve_codex_linux_sandbox_flags",
            return_value=module.CODEX_REVIEW_LINUX_LEGACY_LANDLOCK_FLAGS,
        ):
            command, prompt_delivery, stdin_bytes, resolved_final_path = (
                module._apply_codex_readonly_defaults(
                    codex_path="/fake/codex",
                    rendered_args=[],
                    workspace_root=self.repo,
                    runtime_temp_dir=runtime_temp_dir,
                    final_path=final_path,
                    placeholders=placeholders,
                )
            )
        self.assertEqual(
            command[: len(module.CODEX_REVIEW_LINUX_LEGACY_LANDLOCK_FLAGS)],
            list(module.CODEX_REVIEW_LINUX_LEGACY_LANDLOCK_FLAGS),
        )
        self.assertEqual(
            command[
                len(module.CODEX_REVIEW_LINUX_LEGACY_LANDLOCK_FLAGS) : len(
                    module.CODEX_REVIEW_LINUX_LEGACY_LANDLOCK_FLAGS
                )
                + 8
            ],
            [
                "-s",
                "read-only",
                "--add-dir",
                str(runtime_temp_dir.resolve(strict=False)),
                "--add-dir",
                str(final_path.parent.resolve(strict=False)),
                "exec",
                "-o",
            ],
        )
        self.assertEqual(prompt_delivery, "stdin")
        self.assertIsNotNone(stdin_bytes)
        self.assertIn("Persistent internal Codex readonly review contract:", stdin_bytes.decode("utf-8"))
        self.assertEqual(resolved_final_path.resolve(), final_path.resolve())

    def test_codex_review_rejects_explicit_prompt_for_uncommitted_review(self) -> None:
        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "codex-review",
                "--",
                "Explicit reviewer prompt",
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(
            "codex-review cannot combine an explicit prompt with `--uncommitted`",
            failed.stderr,
        )

    def test_codex_review_rejects_explicit_prompt_when_base_ref_is_managed(self) -> None:
        range_repo, base_commit, head_commit = self._create_review_range_repo(
            "codex-review-explicit-prompt-range"
        )
        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(range_repo),
                "--entrypoint",
                "codex-review",
                "--base-ref",
                base_commit,
                "--head-ref",
                head_commit,
                "--",
                "Explicit reviewer prompt",
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(
            "codex-review cannot combine an explicit prompt with helper-managed `--base`",
            failed.stderr,
        )

    def test_stateful_codex_review_rejects_non_ancestor_frozen_range(self) -> None:
        range_repo, base_commit, head_commit, common_base = (
            self._create_divergent_review_range_repo("codex-review-divergent-range")
        )
        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(range_repo),
                "--entrypoint",
                "codex-review",
                "--base-ref",
                base_commit,
                "--head-ref",
                head_commit,
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(
            "codex-review frozen range requires `--base-ref` to be an ancestor of `--head-ref`",
            failed.stderr,
        )
        self.assertIn(common_base, failed.stderr)
        self.assertFalse((range_repo / ".codex-tmp").exists())

    def test_stateful_codex_review_rejects_unrelated_frozen_range(self) -> None:
        range_repo, base_commit, head_commit = self._create_unrelated_review_range_repo(
            "codex-review-unrelated-range"
        )
        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(range_repo),
                "--entrypoint",
                "codex-review",
                "--base-ref",
                base_commit,
                "--head-ref",
                head_commit,
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(
            "codex-review frozen range requires `--base-ref` to be an ancestor of `--head-ref`",
            failed.stderr,
        )
        self.assertIn("<no common ancestor>", failed.stderr)
        self.assertFalse((range_repo / ".codex-tmp").exists())

    def test_codex_review_exec_options_work_without_custom_prompt(self) -> None:
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "codex-review",
                "--",
                "-C",
                "subdir",
                "--profile",
                "default",
                "--color=never",
                "--oss",
            ],
            env=self._base_env(),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout.splitlines()[-1])["payload"]
        self.assertTrue(payload["used_review_subcommand"])
        self.assertEqual(payload["review_args"][0], "--uncommitted")
        self.assertIn("-C", payload["exec_args"])
        cd_index = payload["exec_args"].index("-C")
        self.assertEqual(
            payload["exec_args"][cd_index + 1],
            str((pathlib.Path(payload["cwd"]) / "subdir").resolve()),
        )
        self.assertIn("--profile", payload["exec_args"])
        self.assertIn("--color=never", payload["exec_args"])
        self.assertIn("--oss", payload["exec_args"])
        self.assertNotIn("-", payload["review_args"])
        self.assertIsNone(payload["prompt_stdin"])

    def test_codex_review_rejects_cd_outside_workspace(self) -> None:
        for cwd_arg in ("..", str(self.root / "escaped-cwd")):
            with self.subTest(cwd_arg=cwd_arg):
                failed = run(
                    [
                        sys.executable,
                        str(SCRIPT_PATH),
                        "--repo",
                        str(self.repo),
                        "--entrypoint",
                        "codex-review",
                        "--",
                        "-C",
                        cwd_arg,
                    ],
                    env=self._base_env(),
                )
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn(
                    "codex-review -C/--cd must stay inside the isolated workspace",
                    failed.stderr,
                )

    def test_codex_review_rejects_exec_runtime_override_flags(self) -> None:
        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "codex-review",
                "--",
                "--sandbox",
                "workspace-write",
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("codex-review manages `--sandbox` itself", failed.stderr)

        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "codex-review",
                "--",
                "--dangerously-bypass-approvals-and-sandbox",
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(
            "codex-review does not allow `--dangerously-bypass-approvals-and-sandbox`",
            failed.stderr,
        )

    def test_codex_review_rejects_short_circuit_flags(self) -> None:
        for flag in ("-h", "--help", "-V", "--version"):
            with self.subTest(flag=flag):
                failed = run(
                    [
                        sys.executable,
                        str(SCRIPT_PATH),
                        "--repo",
                        str(self.repo),
                        "--entrypoint",
                        "codex-review",
                        "--",
                        flag,
                    ],
                    env=self._base_env(),
                )
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn(
                    f"codex-review does not allow `{flag}`",
                    failed.stderr,
                )

    def test_codex_review_rejects_external_file_and_config_options(self) -> None:
        cases = (
            ("--image", "review.png"),
            ("--output-schema", "schema.json"),
            ("--config", "model=\"gpt-5.5\""),
        )
        for option, value in cases:
            with self.subTest(option=option):
                failed = run(
                    [
                        sys.executable,
                        str(SCRIPT_PATH),
                        "--repo",
                        str(self.repo),
                        "--entrypoint",
                        "codex-review",
                        "--",
                        option,
                        value,
                    ],
                    env=self._base_env(),
                )
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn(
                    f"codex-review manages `{option}` itself",
                    failed.stderr,
                )

    def test_codex_review_sanitizes_child_path(self) -> None:
        poison_bin = self.root / "poison-bin"
        poison_bin.mkdir()
        poisoned_env = self._base_env()
        poisoned_env["PATH"] = f"{poison_bin}{os.pathsep}{poisoned_env['PATH']}"

        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "codex-review",
            ],
            env=poisoned_env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout.splitlines()[-1])["payload"]
        self.assertIsNotNone(payload["path_env"])
        self.assertNotIn(str(poison_bin), payload["path_env"])
        self.assertTrue(payload["path_env"].split(os.pathsep)[0].endswith("tool-shims"))

    def test_codex_review_rejects_reserved_subcommands(self) -> None:
        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "codex-review",
                "--",
                "review",
                "--base",
                "master",
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(
            "codex-review already enters `codex exec review`",
            failed.stderr,
        )

    def test_codex_review_rejects_explicit_stdin_prompt_arg(self) -> None:
        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "codex-review",
                "--",
                "-",
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(
            "codex-review child args must not provide stdin prompt directly",
            failed.stderr,
        )

    def test_codex_review_foreground_run_keeps_inherited_environment(self) -> None:
        env = self._base_env()
        env["FAKE_CODEX_REQUIRE_SENTINEL"] = "1"
        env["FAKE_CODEX_SENTINEL"] = "present"
        env["INHERITED_SECRET_TOKEN"] = "top-secret"
        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--entrypoint",
                "codex-review",
            ],
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout.splitlines()[-1])["payload"]
        self.assertEqual(payload["inherited_secret_token"], "top-secret")

    def test_codex_review_reuse_workspace_clears_previous_state(self) -> None:
        prepare = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--prepare-only",
            ],
            env=self._base_env(),
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        workspace_root = pathlib.Path(
            [line.strip() for line in prepare.stdout.splitlines() if line.strip()][-1]
        )

        first_env = self._base_env()
        first_env["FAKE_CODEX_FINAL_MESSAGE"] = "First findings.\n"
        first_start = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(self.repo),
                "--reuse-workspace",
                str(workspace_root),
                "--entrypoint",
                "codex-review",
                "--",
                "-o",
                "custom-final.txt",
            ],
            env=first_env,
        )
        self.assertEqual(first_start.returncode, 0, first_start.stderr)
        state_dir = pathlib.Path(first_start.stdout.strip().splitlines()[-1])

        first_wait = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=first_env,
        )
        self.assertEqual(first_wait.returncode, 0, first_wait.stderr)
        self.assertTrue((workspace_root / "custom-final.txt").is_file())
        self.assertFalse((state_dir / "stdin.txt").exists())
        first_final = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "final",
                "--state-dir",
                str(state_dir),
            ],
            env=first_env,
        )
        self.assertEqual(first_final.stdout, "First findings.\n")

        second_env = self._base_env()
        second_env["FAKE_CODEX_FINAL_MESSAGE"] = "Second findings.\n"
        second_env["FAKE_CODEX_REVIEW_DELAY_SECS"] = "1.5"
        second_start = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(self.repo),
                "--reuse-workspace",
                str(workspace_root),
                "--entrypoint",
                "codex-review",
            ],
            env=second_env,
        )
        self.assertEqual(second_start.returncode, 0, second_start.stderr)
        self.assertEqual(
            pathlib.Path(second_start.stdout.strip().splitlines()[-1]),
            state_dir,
        )
        time.sleep(0.2)
        self.assertFalse((state_dir / "exit_code").exists())
        self.assertFalse((state_dir / "final.txt").exists())
        self.assertFalse((workspace_root / "custom-final.txt").exists())

        status = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "status",
                "--state-dir",
                str(state_dir),
            ],
            env=second_env,
        )
        self.assertEqual(status.returncode, 0, status.stderr)
        summary = json.loads(status.stdout)
        self.assertEqual(summary["status"], "running")
        self.assertTrue(summary["running"])
        self.assertFalse(summary["final_available"])
        self.assertIsNone(summary["exit_code"])

        second_wait = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=second_env,
        )
        self.assertEqual(second_wait.returncode, 0, second_wait.stderr)
        second_final = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "final",
                "--state-dir",
                str(state_dir),
            ],
            env=second_env,
        )
        self.assertEqual(second_final.stdout, "Second findings.\n")

    def test_codex_review_builtin_uncommitted_review_keeps_no_stdin_file(self) -> None:
        env = self._base_env()
        env["FAKE_CODEX_FINAL_MESSAGE"] = "No findings.\n"
        start = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(self.repo),
                "--entrypoint",
                "codex-review",
            ],
            env=env,
        )
        self.assertEqual(start.returncode, 0, start.stderr)
        state_dir = pathlib.Path(start.stdout.strip().splitlines()[-1])
        stdin_path = state_dir / "stdin.txt"
        self.assertFalse(stdin_path.exists())

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)
        self.assertFalse(stdin_path.exists())

        final = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "final",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(final.returncode, 0, final.stderr)
        self.assertEqual(final.stdout, "No findings.\n")

    def test_codex_readonly_stateful_final_requires_final_artifact(self) -> None:
        state_dir = self.root / "stateful-codex-readonly-missing-final"
        state_dir.mkdir()
        stdout_path = state_dir / "stdout.log"
        stdout_path.write_text("progress\nLGTM\n", encoding="utf-8")
        stderr_path = state_dir / "stderr.log"
        stderr_path.write_text("", encoding="utf-8")
        exit_code_path = state_dir / "exit_code"
        exit_code_path.write_text("0\n", encoding="utf-8")
        state = {
            "workspace_root": str(state_dir / "workspace"),
            "entrypoint": "codex-readonly",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(exit_code_path),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "workspace_cleaned": True,
            "review_range": "base..head",
            "final_path": str(state_dir / "final.txt"),
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        final = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "final",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(final.returncode, 0)
        self.assertIn("codex-readonly final artifact is unavailable", final.stderr)

    def test_codex_readonly_wait_fails_closed_when_final_artifact_is_missing(self) -> None:
        state_dir = self.root / "stateful-codex-readonly-missing-final-wait"
        state_dir.mkdir()
        stdout_path = state_dir / "stdout.log"
        stdout_path.write_text("progress\nLGTM\n", encoding="utf-8")
        stderr_path = state_dir / "stderr.log"
        stderr_path.write_text("", encoding="utf-8")
        exit_code_path = state_dir / "exit_code"
        exit_code_path.write_text("0\n", encoding="utf-8")
        state = {
            "workspace_root": str(state_dir / "workspace"),
            "entrypoint": "codex-readonly",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(exit_code_path),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "workspace_cleaned": True,
            "review_range": "base..head",
            "final_path": str(state_dir / "final.txt"),
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(waited.returncode, 1, waited.stderr)
        summary = json.loads(waited.stdout)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["exit_code"], 1)
        self.assertFalse(summary["final_available"])
        self.assertIn("without a final artifact", summary["stderr_tail"])

    def test_codex_review_reuse_workspace_rejects_prior_state_paths_outside_state_dir(self) -> None:
        prepare = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--prepare-only",
            ],
            env=self._base_env(),
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        workspace_root = pathlib.Path(
            [line.strip() for line in prepare.stdout.splitlines() if line.strip()][-1]
        )
        state_dir = workspace_root.parent
        state = {
            "workspace_root": str(workspace_root),
            "pid_path": str(self.root / "outside-pid"),
            "exit_code_path": str(state_dir / "exit_code"),
            "lock_path": str(state_dir / "runner.lock"),
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(self.repo),
                "--reuse-workspace",
                str(workspace_root),
                "--entrypoint",
                "codex-review",
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("pid_path must stay inside", failed.stderr)

    def test_codex_review_reuse_workspace_rejects_prior_diff_file_outside_state_dir(self) -> None:
        prepare = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--prepare-only",
            ],
            env=self._base_env(),
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        workspace_root = pathlib.Path(
            [line.strip() for line in prepare.stdout.splitlines() if line.strip()][-1]
        )
        state_dir = workspace_root.parent
        state = {
            "workspace_root": str(workspace_root),
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(state_dir / "exit_code"),
            "stdout_path": str(state_dir / "stdout.log"),
            "stderr_path": str(state_dir / "stderr.log"),
            "lock_path": str(state_dir / "runner.lock"),
            "runner_spec_path": str(state_dir / "runner-spec.json"),
            "diff_file": str(self.root / "outside.diff"),
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "status",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("diff_file must stay inside", failed.stderr)

    def test_codex_review_final_respects_output_override(self) -> None:
        env = self._base_env()
        env["FAKE_CODEX_FINAL_MESSAGE"] = "Override findings.\n"
        repo, base, head = self._create_review_range_repo("codex-range-output-override")
        start = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(repo),
                "--entrypoint",
                "codex-review",
                "--base-ref",
                base,
                "--head-ref",
                head,
                "--",
                "-o",
                "custom-final.txt",
            ],
            env=env,
        )
        self.assertEqual(start.returncode, 0, start.stderr)
        state_dir = pathlib.Path(start.stdout.strip().splitlines()[-1])

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)

        state = json.loads((state_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(
            state["final_path"],
            str(state_dir / "final.txt"),
        )

        final = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "final",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(final.returncode, 0, final.stderr)
        self.assertEqual(final.stdout, "Override findings.\n")

    def test_codex_review_rejects_output_override_outside_workspace(self) -> None:
        repo, base, head = self._create_review_range_repo("codex-range-output-escape")
        for output_path, expected_message in (
            ("../escaped-final.txt", "must not escape the isolated workspace"),
            (
                str(self.root / "escaped-final.txt"),
                "must be relative to the isolated workspace",
            ),
        ):
            with self.subTest(output_path=output_path):
                failed = run(
                    [
                        sys.executable,
                        str(SCRIPT_PATH),
                        "stateful",
                        "start",
                        "--repo",
                        str(repo),
                        "--entrypoint",
                        "codex-review",
                        "--base-ref",
                        base,
                        "--head-ref",
                        head,
                        "--",
                        "-o",
                        output_path,
                    ],
                    env=self._base_env(),
                )
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn("codex-review --output-last-message", failed.stderr)
                self.assertIn(expected_message, failed.stderr)

    def test_codex_review_rejects_output_override_symlink_escape(self) -> None:
        repo, base, head = self._create_review_range_repo("codex-range-output-symlink")
        escaped_dir = self.root / "escaped-output-symlink"
        escaped_dir.mkdir()
        os.symlink(str(escaped_dir), repo / "link-out")
        self.assertEqual(git(repo, "add", "link-out").returncode, 0)
        git_commit(repo, "add output symlink escape")
        head = git(repo, "rev-parse", "HEAD").stdout.strip()

        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(repo),
                "--entrypoint",
                "codex-review",
                "--base-ref",
                base,
                "--head-ref",
                head,
                "--",
                "-o",
                "link-out/final.txt",
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(
            "must stay inside the isolated workspace after symlink resolution",
            failed.stderr,
        )

    def test_stateful_report_path_is_preserved_after_wait_cleanup(self) -> None:
        start = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(self.repo),
                "--entrypoint",
                "agent",
                "--report-path",
                ".codex-tmp/reports/final.md",
                "--",
                "--output",
                str(self.output_file),
            ],
            env=self._base_env(),
        )
        self.assertEqual(start.returncode, 0, start.stderr)
        state_dir = pathlib.Path(start.stdout.strip().splitlines()[-1])

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)
        summary = json.loads(waited.stdout)
        self.assertEqual(summary["status"], "passed")
        self.assertTrue(summary["report_available"])

        state = json.loads((state_dir / "state.json").read_text(encoding="utf-8"))
        preserved_report_path = pathlib.Path(str(state["report_file"]))
        self.assertTrue(preserved_report_path.is_file())
        self.assertEqual(
            preserved_report_path.read_text(encoding="utf-8"),
            "# Fake review report\n\nLGTM\n",
        )
        self.assertFalse((state_dir / "workspace").exists())

        final = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "final",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(final.returncode, 0, final.stderr)
        self.assertEqual(final.stdout, "# Fake review report\n\nLGTM\n")

    def test_stateful_final_ignores_report_symlink_outside_workspace(self) -> None:
        state_dir = self.root / "stateful-report-symlink-outside"
        state_dir.mkdir()
        workspace_root = state_dir / "workspace"
        workspace_root.mkdir()
        bad_source_root = self.root / "not-a-repo"
        bad_source_root.mkdir()
        secret_file = self.root / "secret.txt"
        secret_file.write_text("top-secret\n", encoding="utf-8")
        report_path = workspace_root / ".codex-tmp" / "reports" / "final.md"
        report_path.parent.mkdir(parents=True)
        report_path.symlink_to(secret_file)
        stdout_path = state_dir / "stdout.log"
        stdout_path.write_text("progress\nNo findings.\n", encoding="utf-8")
        stderr_path = state_dir / "stderr.log"
        stderr_path.write_text("", encoding="utf-8")
        exit_code_path = state_dir / "exit_code"
        exit_code_path.write_text("0\n", encoding="utf-8")
        state = {
            "workspace_root": str(workspace_root),
            "source_root": str(bad_source_root),
            "entrypoint": "agent",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(exit_code_path),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "cleanup_submodule_worktrees": False,
            "workspace_cleaned": False,
            "review_range": "base..head",
            "report_file": str(report_path),
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)
        summary = json.loads(waited.stdout)
        self.assertFalse(summary["report_available"])
        self.assertFalse((state_dir / "report-artifacts").exists())

        final = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "final",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(final.returncode, 0, final.stderr)
        self.assertEqual(final.stdout, "No findings.\n")

    def test_stateful_action_names_remain_valid_review_args(self) -> None:
        extra_args_by_review_arg = {
            "start": ["--repo", "foo"],
            "status": ["--state-dir", "fake-state"],
            "wait": ["--timeout-seconds", "1.5"],
            "final": ["--state-dir", "fake-state"],
        }
        for review_arg in ("start", "status", "wait", "final"):
            with self.subTest(review_arg=review_arg):
                output_file = self.root / f"{review_arg}-payload.json"
                completed = run(
                    [
                        sys.executable,
                        str(SCRIPT_PATH),
                        review_arg,
                        *extra_args_by_review_arg[review_arg],
                        "--output",
                        str(output_file),
                    ],
                    cwd=self.repo,
                    env=self._base_env(),
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                payload = json.loads(output_file.read_text(encoding="utf-8"))
                self.assertIn(review_arg, payload["args"])
                for extra_arg in extra_args_by_review_arg[review_arg]:
                    self.assertIn(extra_arg, payload["args"])

    def test_stateful_namespace_start_supports_default_repo_with_passthrough_args(self) -> None:
        env = self._base_env()
        env["FAKE_CODEX_FINAL_MESSAGE"] = "Namespace findings.\n"
        start = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--entrypoint",
                "codex-review",
                "--",
                "-o",
                "custom-final.txt",
            ],
            cwd=self.repo,
            env=env,
        )
        self.assertEqual(start.returncode, 0, start.stderr)
        state_dir = pathlib.Path(start.stdout.strip().splitlines()[-1])

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)

        final = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "final",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(final.returncode, 0, final.stderr)
        self.assertEqual(final.stdout, "Namespace findings.\n")

    def test_final_falls_back_to_bounded_stdout_tail(self) -> None:
        state_dir = self.root / "stateful-final-fallback"
        state_dir.mkdir()
        stdout_path = state_dir / "stdout.log"
        stdout_path.write_text(
            "".join(f"line-{index}\n" for index in range(50)) + "FINAL-LINE\n",
            encoding="utf-8",
        )
        stderr_path = state_dir / "stderr.log"
        stderr_path.write_text("", encoding="utf-8")
        exit_code_path = state_dir / "exit_code"
        exit_code_path.write_text("0\n", encoding="utf-8")
        state = {
            "workspace_root": str(state_dir / "workspace"),
            "entrypoint": "codex-review",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(exit_code_path),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "workspace_cleaned": True,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        final = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "final",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(final.returncode, 0, final.stderr)
        self.assertEqual(final.stdout, "FINAL-LINE\n")

    def test_codex_review_final_falls_back_to_last_agent_message(self) -> None:
        state_dir = self.root / "stateful-codex-final-fallback"
        state_dir.mkdir()
        stdout_path = state_dir / "stdout.log"
        stdout_path.write_text(
            "\n".join(
                (
                    json.dumps({"type": "thread.started", "thread_id": "thread-1"}),
                    json.dumps(
                        {
                            "type": "item.completed",
                            "item": {
                                "id": "item_0",
                                "type": "agent_message",
                                "text": "No findings.",
                            },
                        }
                    ),
                    json.dumps({"type": "turn.completed", "usage": {"output_tokens": 1}}),
                )
                + ("\n",)
            ),
            encoding="utf-8",
        )
        stderr_path = state_dir / "stderr.log"
        stderr_path.write_text("", encoding="utf-8")
        exit_code_path = state_dir / "exit_code"
        exit_code_path.write_text("0\n", encoding="utf-8")
        state = {
            "workspace_root": str(state_dir / "workspace"),
            "entrypoint": "codex-review",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(exit_code_path),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "workspace_cleaned": True,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        final = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "final",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(final.returncode, 0, final.stderr)
        self.assertEqual(final.stdout, "No findings.\n")

    def test_codex_review_status_reports_launching_without_pid_during_grace_window(self) -> None:
        state_dir = self.root / "stateful-launching"
        state_dir.mkdir()
        runner_spec_path = state_dir / "runner-spec.json"
        runner_spec_path.write_text("{}\n", encoding="utf-8")
        state = {
            "workspace_root": str(state_dir / "workspace"),
            "entrypoint": "codex-review",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(state_dir / "exit_code"),
            "stdout_path": str(state_dir / "stdout.log"),
            "stderr_path": str(state_dir / "stderr.log"),
            "runner_spec_path": str(runner_spec_path),
            "started_at": time.time(),
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        status = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "status",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(status.returncode, 0, status.stderr)
        summary = json.loads(status.stdout)
        self.assertEqual(summary["status"], "launching")
        self.assertTrue(summary["running"])
        self.assertIsNone(summary["pid"])
        self.assertIsNone(summary["exit_code"])

    def test_codex_review_reuse_workspace_rejects_recent_launch_without_pid(self) -> None:
        prepare = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--prepare-only",
            ],
            env=self._base_env(),
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        workspace_root = pathlib.Path(
            [line.strip() for line in prepare.stdout.splitlines() if line.strip()][-1]
        )
        state_dir = workspace_root.parent
        runner_spec_path = state_dir / "runner-spec.json"
        runner_spec_path.write_text("{}\n", encoding="utf-8")
        state = {
            "workspace_root": str(workspace_root),
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(state_dir / "exit_code"),
            "runner_spec_path": str(runner_spec_path),
            "started_at": time.time() + 60,
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        rejected = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(self.repo),
                "--reuse-workspace",
                str(workspace_root),
                "--entrypoint",
                "codex-review",
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("review is still running in reused workspace", rejected.stderr)

    def test_codex_review_prepare_failure_cleans_created_workspace(self) -> None:
        repo, base, head = self._create_review_range_repo("codex-range-explicit-prompt")
        before_dirs = {
            path.name for path in (repo / ".codex-tmp").glob("isolated-review-*")
        }
        before_worktrees = git(repo, "worktree", "list", "--porcelain").stdout.count("worktree ")

        failed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(repo),
                "--entrypoint",
                "codex-review",
                "--base-ref",
                base,
                "--head-ref",
                head,
                "--",
                "Explicit reviewer prompt",
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(
            "codex-review cannot combine an explicit prompt with helper-managed `--base`",
            failed.stderr,
        )
        after_dirs = {
            path.name for path in (repo / ".codex-tmp").glob("isolated-review-*")
        }
        after_worktrees = git(repo, "worktree", "list", "--porcelain").stdout.count("worktree ")
        self.assertEqual(after_dirs, before_dirs)
        self.assertEqual(after_worktrees, before_worktrees)

    def test_run_child_invalid_spec_still_writes_exit_code(self) -> None:
        state_dir = self.root / "stateful-invalid-spec"
        state_dir.mkdir()
        spec_path = state_dir / "runner-spec.json"
        spec_path.write_text("{not-json\n", encoding="utf-8")
        spec_sha256 = hashlib.sha256(spec_path.read_bytes()).hexdigest()

        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "__run-child",
                str(spec_path),
                spec_sha256,
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual((state_dir / "exit_code").read_text(encoding="utf-8"), "1\n")
        self.assertIn(
            "runner bootstrap failed",
            (state_dir / "stderr.log").read_text(encoding="utf-8"),
        )

    def test_run_child_rejects_tampered_spec_digest(self) -> None:
        state_dir = self.root / "stateful-tampered-spec"
        state_dir.mkdir()
        spec_path = state_dir / "runner-spec.json"
        spec_path.write_text("{}\n", encoding="utf-8")
        original_sha256 = hashlib.sha256(spec_path.read_bytes()).hexdigest()
        spec_path.write_text('{"stdout_path": "/tmp/out"}\n', encoding="utf-8")

        completed = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "__run-child",
                str(spec_path),
                original_sha256,
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual((state_dir / "exit_code").read_text(encoding="utf-8"), "1\n")
        self.assertIn(
            "runner spec hash mismatch",
            (state_dir / "stderr.log").read_text(encoding="utf-8"),
        )

    def test_start_prepared_review_records_immediate_exit_under_lock(self) -> None:
        module = self._load_script_module()
        state_dir = self.root / "stateful-immediate-exit"
        state_dir.mkdir()
        workspace_root = state_dir / "workspace"
        workspace_root.mkdir()
        source_root = self.repo
        args = argparse.Namespace(
            prepare_only=False,
            lane="bounded-semantic",
            reuse_workspace=None,
            keep_workspace=False,
            keep_on_failure=False,
        )
        prepared = {
            "args": args,
            "container_dir": str(state_dir),
            "workspace_root": str(workspace_root),
            "source_root": str(source_root),
            "stdin_bytes": None,
            "child_env": {},
            "command": ["true"],
            "placeholders": {
                "{report_file}": None,
                "{review_range}": "base..head",
            },
            "final_path": None,
            "prompt_delivery": "prompt-file",
            "entrypoint_label": "agent",
            "base_ref": "base",
            "head_ref": "head",
            "cleanup_submodule_worktrees": False,
        }

        class _ImmediateExitProcess:
            def __init__(self, returncode: int) -> None:
                self.returncode = returncode

            def poll(self) -> int:
                return self.returncode

        with (
            mock.patch.object(
                module.subprocess,
                "Popen",
                return_value=_ImmediateExitProcess(23),
            ),
            mock.patch.object(module, "_write_runner_terminal_state") as record_terminal_state,
            mock.patch("sys.stdout", new=io.StringIO()),
        ):
            result = module._start_prepared_review(prepared)

        self.assertEqual(result, 0)
        record_terminal_state.assert_called_once_with(
            state_dir / "runner.lock",
            state_dir / "exit_code",
            exit_code=23,
            pid_path=state_dir / "pid",
        )

    def test_start_prepared_review_freezes_codex_review_timeout_policy(self) -> None:
        module = self._load_script_module()
        state_dir = self.root / "stateful-policy-start"
        state_dir.mkdir()
        workspace_root = state_dir / "workspace"
        workspace_root.mkdir()
        source_root = self.repo
        diff_path = state_dir / "review.diff"
        diff_path.write_text("diff --git a/a.txt b/a.txt\n+line\n", encoding="utf-8")
        args = argparse.Namespace(
            prepare_only=False,
            lane="bounded-semantic",
            reuse_workspace=None,
            keep_workspace=False,
            keep_on_failure=False,
        )
        prepared = {
            "args": args,
            "container_dir": str(state_dir),
            "workspace_root": str(workspace_root),
            "source_root": str(source_root),
            "stdin_bytes": None,
            "child_env": {},
            "command": ["true"],
            "placeholders": {
                "{report_file}": None,
                "{review_range}": "base..head",
                "{diff_file}": str(diff_path),
            },
            "final_path": None,
            "prompt_delivery": "prompt-file",
            "entrypoint_label": "codex-review",
            "base_ref": "base",
            "head_ref": "head",
            "cleanup_submodule_worktrees": False,
        }
        policy = {
            "agentic_timeout_budget_seconds": 1800.0,
            "agentic_initial_quiet_seconds": 300.0,
            "agentic_progress_lease_seconds": 480.0,
        }

        class _ImmediateExitProcess:
            def __init__(self, returncode: int) -> None:
                self.returncode = returncode

            def poll(self) -> int:
                return self.returncode

        with (
            mock.patch.object(
                module,
                "_parallel_agentic_review_policy",
                return_value=policy,
            ) as policy_mock,
            mock.patch.object(
                module.subprocess,
                "Popen",
                return_value=_ImmediateExitProcess(0),
            ),
            mock.patch("sys.stdout", new=io.StringIO()),
        ):
            result = module._start_prepared_review(prepared)

        self.assertEqual(result, 0)
        policy_mock.assert_called_once_with(
            workspace_root,
            base_ref="base",
            head_ref="head",
            diff_file=diff_path,
        )
        saved_state = json.loads((state_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(saved_state["codex_review_timeout_budget_seconds"], 1800.0)
        self.assertEqual(saved_state["codex_review_initial_quiet_seconds"], 300.0)
        self.assertEqual(saved_state["codex_review_progress_lease_seconds"], 480.0)

    def test_start_prepared_review_freezes_codex_readonly_timeout_policy(self) -> None:
        module = self._load_script_module()
        state_dir = self.root / "stateful-readonly-policy-start"
        state_dir.mkdir()
        workspace_root = state_dir / "workspace"
        workspace_root.mkdir()
        source_root = self.repo
        diff_path = state_dir / "review.diff"
        diff_path.write_text("diff --git a/a.txt b/a.txt\n+line\n", encoding="utf-8")
        args = argparse.Namespace(
            prepare_only=False,
            lane="bounded-semantic",
            reuse_workspace=None,
            keep_workspace=False,
            keep_on_failure=False,
        )
        prepared = {
            "args": args,
            "container_dir": str(state_dir),
            "workspace_root": str(workspace_root),
            "source_root": str(source_root),
            "stdin_bytes": None,
            "child_env": {},
            "command": ["true"],
            "placeholders": {
                "{report_file}": None,
                "{review_range}": "base..head",
                "{diff_file}": str(diff_path),
            },
            "final_path": str(state_dir / "final.txt"),
            "prompt_delivery": "prompt-file",
            "entrypoint_label": "codex-readonly",
            "base_ref": "base",
            "head_ref": "head",
            "cleanup_submodule_worktrees": False,
        }
        policy = {
            "agentic_timeout_budget_seconds": 1800.0,
            "agentic_initial_quiet_seconds": 300.0,
            "agentic_progress_lease_seconds": 480.0,
        }

        class _ImmediateExitProcess:
            def __init__(self, returncode: int) -> None:
                self.returncode = returncode

            def poll(self) -> int:
                return self.returncode

        with (
            mock.patch.object(
                module,
                "_parallel_agentic_review_policy",
                return_value=policy,
            ) as policy_mock,
            mock.patch.object(
                module.subprocess,
                "Popen",
                return_value=_ImmediateExitProcess(0),
            ),
            mock.patch("sys.stdout", new=io.StringIO()),
        ):
            result = module._start_prepared_review(prepared)

        self.assertEqual(result, 0)
        policy_mock.assert_called_once_with(
            workspace_root,
            base_ref="base",
            head_ref="head",
            diff_file=diff_path,
        )
        saved_state = json.loads((state_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(saved_state["codex_readonly_timeout_budget_seconds"], 1800.0)
        self.assertEqual(saved_state["codex_readonly_initial_quiet_seconds"], 300.0)
        self.assertEqual(saved_state["codex_readonly_progress_lease_seconds"], 480.0)

    def test_wait_fails_fast_for_unknown_state_without_exit_code(self) -> None:
        state_dir = self.root / "stateful-unknown"
        state_dir.mkdir()
        runner_spec_path = state_dir / "runner-spec.json"
        runner_spec_path.write_text("{}\n", encoding="utf-8")
        state = {
            "workspace_root": str(state_dir / "workspace"),
            "entrypoint": "codex-review",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(state_dir / "exit_code"),
            "stdout_path": str(state_dir / "stdout.log"),
            "stderr_path": str(state_dir / "stderr.log"),
            "runner_spec_path": str(runner_spec_path),
            "started_at": time.time() - 10,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(waited.returncode, 0)
        self.assertIn(
            "review state became unknown without exit code",
            waited.stderr,
        )

    def test_wait_preserves_success_exit_code_when_cleanup_fails(self) -> None:
        state_dir = self.root / "stateful-cleanup-error"
        state_dir.mkdir()
        workspace_root = state_dir / "workspace"
        workspace_root.mkdir()
        bad_source_root = self.root / "not-a-repo"
        bad_source_root.mkdir()
        exit_code_path = state_dir / "exit_code"
        exit_code_path.write_text("0\n", encoding="utf-8")
        state = {
            "workspace_root": str(workspace_root),
            "source_root": str(bad_source_root),
            "entrypoint": "codex-review",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(exit_code_path),
            "stdout_path": str(state_dir / "stdout.log"),
            "stderr_path": str(state_dir / "stderr.log"),
            "cleanup_submodule_worktrees": False,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)
        self.assertIn(
            "stateful source_root does not recognize workspace_root",
            waited.stderr,
        )
        summary = json.loads(waited.stdout)
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["exit_code"], 0)
        self.assertFalse(summary["workspace_cleaned"])

    def test_wait_prunes_missing_workspace_before_marking_clean(self) -> None:
        prepare = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--prepare-only",
            ],
            env=self._base_env(),
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        workspace_root = pathlib.Path(
            [line.strip() for line in prepare.stdout.splitlines() if line.strip()][-1]
        )
        state_dir = workspace_root.parent
        before_prune = git(self.repo, "worktree", "list", "--porcelain").stdout
        self.assertIn(str(workspace_root.resolve(strict=False)), before_prune)
        shutil.rmtree(workspace_root)

        exit_code_path = state_dir / "exit_code"
        exit_code_path.write_text("0\n", encoding="utf-8")
        state = {
            "workspace_root": str(workspace_root),
            "source_root": str(self.repo),
            "entrypoint": "codex-review",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(exit_code_path),
            "stdout_path": str(state_dir / "stdout.log"),
            "stderr_path": str(state_dir / "stderr.log"),
            "cleanup_submodule_worktrees": False,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)
        summary = json.loads(waited.stdout)
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["exit_code"], 0)
        self.assertTrue(summary["workspace_cleaned"])
        after_prune = git(self.repo, "worktree", "list", "--porcelain").stdout
        self.assertNotIn(str(workspace_root.resolve(strict=False)), after_prune)

    def test_wait_preserves_success_exit_code_when_missing_workspace_source_root_is_unknown(
        self,
    ) -> None:
        prepare = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--prepare-only",
            ],
            env=self._base_env(),
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        workspace_root = pathlib.Path(
            [line.strip() for line in prepare.stdout.splitlines() if line.strip()][-1]
        )
        state_dir = workspace_root.parent
        shutil.rmtree(workspace_root)

        unrelated_repo = self._create_plain_repo("missing-workspace-unrelated-source-root")
        exit_code_path = state_dir / "exit_code"
        exit_code_path.write_text("0\n", encoding="utf-8")
        state = {
            "workspace_root": str(workspace_root),
            "source_root": str(unrelated_repo),
            "entrypoint": "codex-review",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(exit_code_path),
            "stdout_path": str(state_dir / "stdout.log"),
            "stderr_path": str(state_dir / "stderr.log"),
            "cleanup_submodule_worktrees": False,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)
        self.assertIn(
            "stateful source_root does not recognize missing workspace_root",
            waited.stderr,
        )
        summary = json.loads(waited.stdout)
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["exit_code"], 0)
        self.assertFalse(summary["workspace_cleaned"])

    def test_wait_prunes_missing_workspace_submodule_registrations(self) -> None:
        prepare = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--repo",
                str(self.repo),
                "--prepare-only",
            ],
            env=self._base_env(),
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        workspace_root = pathlib.Path(
            [line.strip() for line in prepare.stdout.splitlines() if line.strip()][-1]
        )
        state_dir = workspace_root.parent
        target_submodule = workspace_root / "deps/sub"
        root_before_prune = git(self.repo, "worktree", "list", "--porcelain").stdout
        submodule_before_prune = git(
            self.repo / "deps/sub",
            "worktree",
            "list",
            "--porcelain",
        ).stdout
        self.assertIn(str(workspace_root.resolve(strict=False)), root_before_prune)
        self.assertIn(str(target_submodule.resolve(strict=False)), submodule_before_prune)
        shutil.rmtree(workspace_root)

        exit_code_path = state_dir / "exit_code"
        exit_code_path.write_text("0\n", encoding="utf-8")
        state = {
            "workspace_root": str(workspace_root),
            "source_root": str(self.repo),
            "entrypoint": "codex-review",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(exit_code_path),
            "stdout_path": str(state_dir / "stdout.log"),
            "stderr_path": str(state_dir / "stderr.log"),
            "cleanup_submodule_worktrees": True,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)
        summary = json.loads(waited.stdout)
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["exit_code"], 0)
        self.assertTrue(summary["workspace_cleaned"])
        root_after_prune = git(self.repo, "worktree", "list", "--porcelain").stdout
        submodule_after_prune = git(
            self.repo / "deps/sub",
            "worktree",
            "list",
            "--porcelain",
        ).stdout
        self.assertNotIn(str(workspace_root.resolve(strict=False)), root_after_prune)
        self.assertNotIn(str(target_submodule.resolve(strict=False)), submodule_after_prune)

    def test_status_prefers_exit_code_over_live_pid(self) -> None:
        state_dir = self.root / "stateful-terminal-status"
        state_dir.mkdir()
        exit_code_path = state_dir / "exit_code"
        exit_code_path.write_text("0\n", encoding="utf-8")
        pid_path = state_dir / "pid"
        pid_path.write_text(f"{os.getpid()}\n", encoding="utf-8")
        state = {
            "workspace_root": str(state_dir / "workspace"),
            "source_root": str(self.repo),
            "entrypoint": "codex-review",
            "pid_path": str(pid_path),
            "exit_code_path": str(exit_code_path),
            "stdout_path": str(state_dir / "stdout.log"),
            "stderr_path": str(state_dir / "stderr.log"),
            "cleanup_submodule_worktrees": False,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        status = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "status",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(status.returncode, 0, status.stderr)
        summary = json.loads(status.stdout)
        self.assertEqual(summary["status"], "passed")
        self.assertFalse(summary["running"])
        self.assertEqual(summary["exit_code"], 0)

    def test_status_ignores_live_pid_when_runner_identity_does_not_match(self) -> None:
        state_dir = self.root / "stateful-stale-live-pid"
        state_dir.mkdir()
        runner_spec_path = state_dir / "runner-spec.json"
        runner_spec_path.write_text("{}\n", encoding="utf-8")
        pid_path = state_dir / "pid"
        pid_path.write_text(f"{os.getpid()}\n", encoding="utf-8")
        state = {
            "workspace_root": str(state_dir / "workspace"),
            "entrypoint": "codex-review",
            "pid_path": str(pid_path),
            "exit_code_path": str(state_dir / "exit_code"),
            "stdout_path": str(state_dir / "stdout.log"),
            "stderr_path": str(state_dir / "stderr.log"),
            "runner_spec_path": str(runner_spec_path),
            "started_at": time.time() - 10,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        status = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "status",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(status.returncode, 0, status.stderr)
        summary = json.loads(status.stdout)
        self.assertEqual(summary["status"], "unknown")
        self.assertFalse(summary["running"])
        self.assertIsNone(summary["exit_code"])

    def test_status_terminalizes_stalled_codex_review_after_initial_quiet(self) -> None:
        state_dir = self.root / "stateful-stalled-status"
        state_dir.mkdir()
        workspace_root = state_dir / "workspace"
        workspace_root.mkdir()
        stdout_path = state_dir / "stdout.log"
        stderr_path = state_dir / "stderr.log"
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        state = {
            "workspace_root": str(workspace_root),
            "source_root": str(self.repo),
            "entrypoint": "codex-review",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(state_dir / "exit_code"),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "started_at": time.time() - 400.0,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        status = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "status",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(status.returncode, 0, status.stderr)
        summary = json.loads(status.stdout)
        self.assertEqual(
            summary["exit_code"],
            124,
        )
        self.assertEqual(summary["status"], "failed")
        self.assertFalse(summary["running"])
        self.assertIn("without reviewer output", summary["stderr_tail"])
        saved_state = json.loads((state_dir / "state.json").read_text(encoding="utf-8"))
        self.assertTrue(
            "codex_review_timeout_budget_seconds" in saved_state
            or "codex_review_policy_error" in saved_state
        )

    def test_wait_returns_timeout_for_stalled_codex_review_output(self) -> None:
        state_dir = self.root / "stateful-stalled-wait"
        state_dir.mkdir()
        workspace_root = state_dir / "workspace"
        workspace_root.mkdir()
        stdout_path = state_dir / "stdout.log"
        stderr_path = state_dir / "stderr.log"
        stdout_path.write_text("progress\n", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        stale_output_at = time.time() - 700.0
        os.utime(stdout_path, (stale_output_at, stale_output_at))
        state = {
            "workspace_root": str(workspace_root),
            "source_root": str(self.repo),
            "entrypoint": "codex-review",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(state_dir / "exit_code"),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "started_at": stale_output_at - 100.0,
            "codex_review_last_output_at": stale_output_at,
            "keep_on_failure": True,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(waited.returncode, 124, waited.stderr)
        summary = json.loads(waited.stdout)
        self.assertEqual(summary["exit_code"], 124)
        self.assertEqual(summary["status"], "failed")
        self.assertFalse(summary["running"])
        self.assertIn("without new reviewer output", summary["stderr_tail"])

    def test_wait_returns_timeout_for_stalled_codex_readonly_output(self) -> None:
        state_dir = self.root / "stateful-readonly-stalled-wait"
        state_dir.mkdir()
        workspace_root = state_dir / "workspace"
        workspace_root.mkdir()
        stdout_path = state_dir / "stdout.log"
        stderr_path = state_dir / "stderr.log"
        stdout_path.write_text("progress\n", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        stale_output_at = time.time() - 700.0
        os.utime(stdout_path, (stale_output_at, stale_output_at))
        state = {
            "workspace_root": str(workspace_root),
            "source_root": str(self.repo),
            "entrypoint": "codex-readonly",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(state_dir / "exit_code"),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "started_at": stale_output_at + 10.0,
            "codex_readonly_timeout_budget_seconds": 1000.0,
            "codex_readonly_initial_quiet_seconds": 30.0,
            "codex_readonly_progress_lease_seconds": 30.0,
            "codex_readonly_last_output_at": stale_output_at,
            "keep_on_failure": True,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(waited.returncode, 124, waited.stderr)
        summary = json.loads(waited.stdout)
        self.assertEqual(summary["exit_code"], 124)
        self.assertEqual(summary["status"], "failed")
        self.assertFalse(summary["running"])
        self.assertIn("without new reviewer output", summary["stderr_tail"])

    def test_stateful_codex_review_timeout_settles_live_runner_after_sigterm(self) -> None:
        module = self._load_script_module()
        state_dir = self.root / "stateful-live-timeout"
        state_dir.mkdir()
        workspace_root = state_dir / "workspace"
        workspace_root.mkdir()
        stdout_path = state_dir / "stdout.log"
        stderr_path = state_dir / "stderr.log"
        stdout_path.write_text("progress\n", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        pid_path = state_dir / "pid"
        pid_path.write_text("12345\n", encoding="utf-8")
        state = {
            "workspace_root": str(workspace_root),
            "source_root": str(self.repo),
            "entrypoint": "codex-review",
            "pid_path": str(pid_path),
            "exit_code_path": str(state_dir / "exit_code"),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "started_at": 1000.0,
            "codex_review_timeout_budget_seconds": 60.0,
            "codex_review_initial_quiet_seconds": 30.0,
            "codex_review_progress_lease_seconds": 30.0,
            "codex_review_last_output_at": 1000.0,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        with mock.patch.object(
            module,
            "_state_lock_is_held",
            side_effect=[True, False],
        ), mock.patch.object(
            module,
            "_state_launch_pending",
            return_value=False,
        ), mock.patch.object(
            module.time,
            "time",
            side_effect=[2000.0, 2000.1],
        ), mock.patch.object(
            module,
            "_terminate_parallel_runner_process_group",
        ) as terminate_mock, mock.patch.object(
            module,
            "_force_stateful_terminal_exit",
        ) as force_mock:
            module._maybe_enforce_stateful_codex_review_timeout(
                state_dir,
                state,
                settle_timeout=True,
            )

        terminate_mock.assert_called_once_with(12345, sig=module.signal.SIGTERM)
        force_mock.assert_called_once()
        saved_state = json.loads((state_dir / "state.json").read_text(encoding="utf-8"))
        self.assertTrue(saved_state["codex_review_timed_out"])
        self.assertIn("codex_review_term_sent_at", saved_state)

    def test_stateful_codex_readonly_timeout_settles_live_runner_after_sigterm(self) -> None:
        module = self._load_script_module()
        state_dir = self.root / "stateful-readonly-live-timeout"
        state_dir.mkdir()
        workspace_root = state_dir / "workspace"
        workspace_root.mkdir()
        stdout_path = state_dir / "stdout.log"
        stderr_path = state_dir / "stderr.log"
        stdout_path.write_text("progress\n", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        pid_path = state_dir / "pid"
        pid_path.write_text("12345\n", encoding="utf-8")
        state = {
            "workspace_root": str(workspace_root),
            "source_root": str(self.repo),
            "entrypoint": "codex-readonly",
            "pid_path": str(pid_path),
            "exit_code_path": str(state_dir / "exit_code"),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "started_at": 1000.0,
            "codex_readonly_timeout_budget_seconds": 60.0,
            "codex_readonly_initial_quiet_seconds": 30.0,
            "codex_readonly_progress_lease_seconds": 30.0,
            "codex_readonly_last_output_at": 1000.0,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        with mock.patch.object(
            module,
            "_state_lock_is_held",
            side_effect=[True, False],
        ), mock.patch.object(
            module,
            "_state_launch_pending",
            return_value=False,
        ), mock.patch.object(
            module.time,
            "time",
            side_effect=[2000.0, 2000.1],
        ), mock.patch.object(
            module,
            "_terminate_parallel_runner_process_group",
        ) as terminate_mock, mock.patch.object(
            module,
            "_force_stateful_terminal_exit",
        ) as force_mock:
            module._maybe_enforce_stateful_codex_readonly_timeout(
                state_dir,
                state,
                settle_timeout=True,
            )

        terminate_mock.assert_called_once_with(12345, sig=module.signal.SIGTERM)
        force_mock.assert_called_once()
        saved_state = json.loads((state_dir / "state.json").read_text(encoding="utf-8"))
        self.assertTrue(saved_state["codex_readonly_timed_out"])
        self.assertIn("codex_readonly_term_sent_at", saved_state)

    def test_final_refreshes_stalled_codex_review_before_running_check(self) -> None:
        state_dir = self.root / "stateful-stalled-final"
        state_dir.mkdir()
        workspace_root = state_dir / "workspace"
        workspace_root.mkdir()
        stdout_path = state_dir / "stdout.log"
        stderr_path = state_dir / "stderr.log"
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        state = {
            "workspace_root": str(workspace_root),
            "source_root": str(self.repo),
            "entrypoint": "codex-review",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(state_dir / "exit_code"),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "started_at": time.time() - 400.0,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        final = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "final",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(final.returncode, 0)
        self.assertIn("no final reviewer message available", final.stderr)
        self.assertNotIn("review is still running", final.stderr)
        self.assertEqual(
            (state_dir / "exit_code").read_text(encoding="utf-8").strip(),
            "124",
        )

    def test_stateful_status_reports_invalid_json_state_cleanly(self) -> None:
        state_dir = self.root / "stateful-invalid-json"
        state_dir.mkdir()
        (state_dir / "state.json").write_text("{\n", encoding="utf-8")

        status = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "status",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(status.returncode, 0)
        self.assertIn("invalid JSON file", status.stderr)

    def test_stateful_status_reports_missing_workspace_root_cleanly(self) -> None:
        state_dir = self.root / "stateful-missing-workspace-root"
        state_dir.mkdir()
        state = {
            "entrypoint": "codex-review",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(state_dir / "exit_code"),
            "stdout_path": str(state_dir / "stdout.log"),
            "stderr_path": str(state_dir / "stderr.log"),
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        status = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "status",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(status.returncode, 0)
        self.assertIn(
            "review state missing required field: workspace_root",
            status.stderr,
        )

    def test_stateful_status_rejects_stdout_path_outside_state_dir(self) -> None:
        state_dir = self.root / "stateful-outside-stdout"
        state_dir.mkdir()
        workspace_root = state_dir / "workspace"
        workspace_root.mkdir()
        secret_stdout = self.root / "secret-stdout.log"
        secret_stdout.write_text("outside\n", encoding="utf-8")
        state = {
            "workspace_root": str(workspace_root),
            "entrypoint": "codex-review",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(state_dir / "exit_code"),
            "stdout_path": str(secret_stdout),
            "stderr_path": str(state_dir / "stderr.log"),
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        status = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "status",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(status.returncode, 0)
        self.assertIn("stdout_path must stay inside", status.stderr)

    def test_read_exit_code_tolerates_raced_unlink(self) -> None:
        module = self._load_script_module()
        path = self.root / "raced-exit-code"
        with mock.patch.object(pathlib.Path, "read_text", side_effect=FileNotFoundError):
            self.assertIsNone(module._read_exit_code(path))

    def test_read_pid_tolerates_raced_unlink(self) -> None:
        module = self._load_script_module()
        path = self.root / "raced-pid"
        with mock.patch.object(pathlib.Path, "read_text", side_effect=FileNotFoundError):
            self.assertIsNone(module._read_pid(path))

    def test_wait_preserves_success_exit_code_when_source_root_does_not_own_workspace(self) -> None:
        state_dir = self.root / "stateful-unregistered-source-root"
        state_dir.mkdir()
        workspace_root = state_dir / "workspace"
        workspace_root.mkdir()
        unrelated_repo = self._create_plain_repo("unrelated-source-root")
        exit_code_path = state_dir / "exit_code"
        exit_code_path.write_text("0\n", encoding="utf-8")
        state = {
            "workspace_root": str(workspace_root),
            "source_root": str(unrelated_repo),
            "entrypoint": "codex-review",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(exit_code_path),
            "stdout_path": str(state_dir / "stdout.log"),
            "stderr_path": str(state_dir / "stderr.log"),
            "cleanup_submodule_worktrees": False,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)
        self.assertIn(
            "stateful source_root does not recognize workspace_root",
            waited.stderr,
        )

    def test_wait_tolerates_blank_exit_code_file(self) -> None:
        state_dir = self.root / "stateful-blank-exit-code"
        state_dir.mkdir()
        runner_spec_path = state_dir / "runner-spec.json"
        runner_spec_path.write_text("{}\n", encoding="utf-8")
        (state_dir / "exit_code").write_text("", encoding="utf-8")
        state = {
            "workspace_root": str(state_dir / "workspace"),
            "entrypoint": "codex-review",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(state_dir / "exit_code"),
            "stdout_path": str(state_dir / "stdout.log"),
            "stderr_path": str(state_dir / "stderr.log"),
            "runner_spec_path": str(runner_spec_path),
            "started_at": time.time() - 10,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(waited.returncode, 0)
        self.assertIn(
            "review state became unknown without exit code",
            waited.stderr,
        )

    def test_wait_tolerates_malformed_pid_file(self) -> None:
        state_dir = self.root / "stateful-malformed-pid"
        state_dir.mkdir()
        runner_spec_path = state_dir / "runner-spec.json"
        runner_spec_path.write_text("{}\n", encoding="utf-8")
        (state_dir / "pid").write_text("not-a-pid\n", encoding="utf-8")
        state = {
            "workspace_root": str(state_dir / "workspace"),
            "entrypoint": "codex-review",
            "pid_path": str(state_dir / "pid"),
            "exit_code_path": str(state_dir / "exit_code"),
            "stdout_path": str(state_dir / "stdout.log"),
            "stderr_path": str(state_dir / "stderr.log"),
            "runner_spec_path": str(runner_spec_path),
            "started_at": time.time() - 10,
            "workspace_cleaned": False,
            "review_range": "base..head",
        }
        (state_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=self._base_env(),
        )
        self.assertNotEqual(waited.returncode, 0)
        self.assertIn(
            "review state became unknown without exit code",
            waited.stderr,
        )

    def test_codex_review_status_reports_running_with_builtin_review_scope(self) -> None:
        env = self._base_env()
        env["FAKE_CODEX_REVIEW_DELAY_SECS"] = "1.5"
        start = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "start",
                "--repo",
                str(self.repo),
                "--entrypoint",
                "codex-review",
            ],
            env=env,
        )
        self.assertEqual(start.returncode, 0, start.stderr)
        state_dir = pathlib.Path(start.stdout.strip().splitlines()[-1])
        time.sleep(0.2)

        status = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "status",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(status.returncode, 0, status.stderr)
        summary = json.loads(status.stdout)
        self.assertEqual(summary["entrypoint"], "codex-review")
        self.assertTrue(summary["running"])
        self.assertEqual(summary["status"], "running")
        self.assertIsInstance(summary["pid"], int)

        waited = run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "stateful",
                "wait",
                "--state-dir",
                str(state_dir),
            ],
            env=env,
        )
        self.assertEqual(waited.returncode, 0, waited.stderr)
        payload = json.loads(
            (state_dir / "stdout.log").read_text(encoding="utf-8").splitlines()[-1]
        )["payload"]
        self.assertIsNone(payload["review_base"])
        self.assertTrue(payload["used_review_subcommand"])
        self.assertIn("review", payload["args"])
        self.assertEqual(payload["review_args"][0], "--uncommitted")
        self.assertNotIn("-", payload["review_args"])
        self.assertIsNone(payload["prompt_stdin"])
        self.assertIsNone(payload["diff_file"])
        self.assertIn("--add-dir", payload["args"])
        self.assertTrue(payload["tmpdir"].endswith("codex-review-tmp"))


if __name__ == "__main__":
    unittest.main()
