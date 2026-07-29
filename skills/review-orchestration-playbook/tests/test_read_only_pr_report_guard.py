from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
GUARD = SKILL_ROOT / "scripts" / "named_lane_guard"
RECEIVER = SKILL_ROOT / "scripts" / "read_only_pr_report.py"
RUNTIME = SKILL_ROOT / "scripts" / "review_runtime" / "read_only_report_guard.py"
BOOTSTRAP = SKILL_ROOT / "scripts" / "review_runtime" / "catalog_bootstrap.py"
RUNTIME_INIT = SKILL_ROOT / "scripts" / "review_runtime" / "__init__.py"
SCHEMA = SKILL_ROOT / "references" / "pr-readiness-read-only-report.schema.json"
CONTROL_MANIFEST = (
    SKILL_ROOT / "references" / "read-only-pr-report-control-manifest.json"
)
PROBE_CASES = (
    SKILL_ROOT.parent
    / "change-delivery-workflow"
    / "tests"
    / "fixtures"
    / "read-only-pr-probe-cases.json"
)
PROFILE = "validate-read-only-pr-report"
CONTROL_DIGEST_PATTERN = re.compile(
    r'(_READ_ONLY_REPORT_CONTROL_MANIFEST_SHA256 = \(\n    ")'
    r"[0-9a-f]{64}"
    r'("\n\))'
)
RECEIVER_TEST_HOOK = r"""

_TEST_ORIGINAL_VALIDATE_REPORT = validate_report


def validate_report(report):
    mode = os.environ.get("CODEX_REPORT_GUARD_TEST_MODE")
    target = os.environ.get("CODEX_REPORT_GUARD_TEST_TARGET")
    replacement = os.environ.get("CODEX_REPORT_GUARD_TEST_REPLACEMENT")
    backup = os.environ.get("CODEX_REPORT_GUARD_TEST_BACKUP")
    if mode in {"schema-aba", "receiver-aba"}:
        os.replace(target, backup)
        os.replace(replacement, target)
        try:
            return _TEST_ORIGINAL_VALIDATE_REPORT(report)
        finally:
            os.replace(target, replacement)
            os.replace(backup, target)
    result = _TEST_ORIGINAL_VALIDATE_REPORT(report)
    if mode == "persistent-replacement":
        os.replace(replacement, target)
    elif mode == "byte-drift":
        with open(target, "r+b", buffering=0) as stream:
            initial = stream.read(1)
            stream.seek(0)
            stream.write(b"#" if initial != b"#" else b'"')
            os.fsync(stream.fileno())
    elif mode == "access-drift":
        os.chmod(target, os.stat(target, follow_symlinks=False).st_mode | 0o020)
    return result
"""


def valid_report() -> dict[str, object]:
    fixture = json.loads(PROBE_CASES.read_text(encoding="utf-8"))
    return copy.deepcopy(
        next(
            case["expected"]["terminal_result"]
            for case in fixture["cases"]
            if case["name"] == "selected-pr-base-head-blocked"
        )
    )


def copy_guard_bundle(root: Path) -> Path:
    bundle = root / "review-orchestration-playbook"
    paths = (
        GUARD,
        RECEIVER,
        RUNTIME,
        BOOTSTRAP,
        RUNTIME_INIT,
        SCHEMA,
        CONTROL_MANIFEST,
    )
    for source in paths:
        relative = source.relative_to(SKILL_ROOT)
        destination = bundle / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    return bundle


def rotate_control_manifest(bundle: Path) -> str:
    manifest_path = bundle / "references" / "read-only-pr-report-control-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for artifact in (*manifest["control_sources"], *manifest["artifacts"]):
        artifact["sha256"] = hashlib.sha256(
            (bundle / artifact["path"]).read_bytes()
        ).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    guard_path = bundle / "scripts" / "named_lane_guard"
    updated, count = CONTROL_DIGEST_PATTERN.subn(
        rf"\g<1>{digest}\g<2>",
        guard_path.read_text(encoding="utf-8"),
    )
    if count != 1:
        raise AssertionError("guard manifest digest anchor is not unique")
    guard_path.write_text(updated, encoding="utf-8")
    return digest


def add_receiver_test_hook(bundle: Path) -> None:
    receiver = bundle / "scripts" / "read_only_pr_report.py"
    receiver.write_text(
        receiver.read_text(encoding="utf-8") + RECEIVER_TEST_HOOK,
        encoding="utf-8",
    )
    rotate_control_manifest(bundle)


def add_pre_execution_replacement_hook(bundle: Path) -> None:
    guard = bundle / "scripts" / "named_lane_guard"
    source = guard.read_text(encoding="utf-8")
    admission = "    records = _read_only_report_control_records(manifest_bytes)\n"
    capture_end = "    schema_bytes = _validate_bound_companion(schema_path)\n"
    if source.count(admission) != 1 or source.count(capture_end) != 1:
        raise AssertionError("guard capture anchors are not unique")
    source = source.replace(
        admission,
        admission
        + """    _test_target = os.environ.get("CODEX_CONTROL_CAPTURE_TARGET")
    _test_replacement = os.environ.get("CODEX_CONTROL_CAPTURE_REPLACEMENT")
    _test_backup = os.environ.get("CODEX_CONTROL_CAPTURE_BACKUP")
    if _test_target and _test_replacement and _test_backup:
        os.replace(_test_target, _test_backup)
        os.replace(_test_replacement, _test_target)
""",
        1,
    )
    source = source.replace(
        capture_end,
        capture_end
        + """    if _test_target and _test_replacement and _test_backup:
        os.replace(_test_target, _test_replacement)
        os.replace(_test_backup, _test_target)
""",
        1,
    )
    guard.write_text(source, encoding="utf-8")


def run_guard(
    bundle: Path,
    report: object,
    *,
    report_path: Path | None = None,
    test_environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    guard = (bundle / "scripts" / "named_lane_guard").resolve()
    command = [
        sys.executable,
        "-I",
        "-B",
        "-S",
        str(guard),
        PROFILE,
        "-" if report_path is None else str(report_path),
    ]
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    if test_environment:
        environment.update(test_environment)
    payload = (
        json.dumps(report, separators=(",", ":")).encode("utf-8")
        if report_path is None
        else None
    )
    return subprocess.run(
        command,
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
        env=environment,
    )


class ReadOnlyPrReportGuardTest(unittest.TestCase):
    def test_valid_stdin_and_regular_file_paths_are_accepted(self) -> None:
        report = valid_report()
        with tempfile.TemporaryDirectory() as directory:
            bundle = copy_guard_bundle(Path(directory).resolve())
            report_path = Path(directory).resolve() / "report.json"
            report_path.write_text(
                json.dumps(report, separators=(",", ":")),
                encoding="utf-8",
            )
            for name, path in (("stdin", None), ("file", report_path)):
                with self.subTest(source=name):
                    completed = run_guard(bundle, report, report_path=path)
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    terminal = json.loads(completed.stdout)
                    self.assertEqual(terminal["classification"], "accepted")
                    control = terminal["control"]
                    self.assertEqual(control["profile"], PROFILE)
                    self.assertEqual(control["profile_version"], 1)
                    manifest = json.loads(
                        (
                            bundle
                            / "references"
                            / "read-only-pr-report-control-manifest.json"
                        ).read_text(encoding="utf-8")
                    )
                    records = {
                        artifact["role"]: artifact["sha256"]
                        for artifact in manifest["artifacts"]
                    }
                    self.assertEqual(
                        control["receiver_sha256"],
                        records["receiver"],
                    )
                    self.assertEqual(
                        control["schema_sha256"],
                        records["schema"],
                    )
                    self.assertEqual(completed.stderr, b"")

    def test_direct_receiver_and_missing_manifest_fail_closed(self) -> None:
        report = valid_report()
        direct = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-S",
                str(RECEIVER),
                "validate-report",
                "-",
            ],
            input=json.dumps(report).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=20,
        )
        self.assertEqual(direct.returncode, 2)
        self.assertEqual(json.loads(direct.stdout)["classification"], "rejected")
        self.assertIn(b"guard bindings are unavailable", direct.stdout)

        with tempfile.TemporaryDirectory() as directory:
            bundle = copy_guard_bundle(Path(directory).resolve())
            (
                bundle / "references" / "read-only-pr-report-control-manifest.json"
            ).unlink()
            completed = run_guard(bundle, report)
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn(b'"classification": "accepted"', completed.stdout)
        self.assertNotIn(b"Traceback", completed.stderr)
        self.assertLess(len(completed.stdout) + len(completed.stderr), 2_000)

        with tempfile.TemporaryDirectory() as directory:
            bundle = copy_guard_bundle(Path(directory).resolve())
            manifest_path = (
                bundle / "references" / "read-only-pr-report-control-manifest.json"
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["loader"]["path"] = "scripts/read_only_pr_report.py"
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n",
                encoding="utf-8",
            )
            rotate_control_manifest(bundle)
            completed = run_guard(bundle, report)
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn(b'"classification": "accepted"', completed.stdout)
        self.assertIn(b"control manifest loader is invalid", completed.stderr)
        self.assertNotIn(b"Traceback", completed.stderr)

    def test_relaxed_schema_replacement_and_restore_cannot_accept_forgery(
        self,
    ) -> None:
        forged = valid_report()
        forged["merge_ready"] = True
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            bundle = copy_guard_bundle(root)
            add_receiver_test_hook(bundle)
            schema = bundle / "references" / "pr-readiness-read-only-report.schema.json"
            original = schema.read_bytes()
            marker = b'    "merge_ready": {\n      "const": false\n    },'
            relaxed = marker.replace(b"false", b"true ", 1)
            self.assertEqual(len(marker), len(relaxed))
            self.assertIn(marker, original)
            replacement = schema.with_name("relaxed-schema.json")
            backup = schema.with_name("trusted-schema.backup")
            replacement.write_bytes(original.replace(marker, relaxed, 1))
            replacement.chmod(stat.S_IMODE(schema.stat().st_mode))
            os.utime(
                replacement,
                ns=(schema.stat().st_atime_ns, schema.stat().st_mtime_ns),
            )
            self.assertEqual(replacement.stat().st_size, schema.stat().st_size)
            completed = run_guard(
                bundle,
                forged,
                test_environment={
                    "CODEX_REPORT_GUARD_TEST_MODE": "schema-aba",
                    "CODEX_REPORT_GUARD_TEST_TARGET": str(schema),
                    "CODEX_REPORT_GUARD_TEST_REPLACEMENT": str(replacement),
                    "CODEX_REPORT_GUARD_TEST_BACKUP": str(backup),
                },
            )
            self.assertEqual(schema.read_bytes(), original)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["classification"], "rejected")
        self.assertIn(b"closed report schema rejected", completed.stdout)
        self.assertNotIn(b'"classification": "accepted"', completed.stdout)

    def test_receiver_replacement_and_restore_never_executes_replacement(
        self,
    ) -> None:
        report = valid_report()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            bundle = copy_guard_bundle(root)
            add_receiver_test_hook(bundle)
            receiver = bundle / "scripts" / "read_only_pr_report.py"
            original = receiver.read_bytes()
            marker_path = root / "replacement-executed"
            replacement_source = (
                f"from pathlib import Path\n"
                f"Path({str(marker_path)!r}).write_text('executed')\n"
            ).encode("utf-8")
            self.assertLess(len(replacement_source), len(original))
            replacement = receiver.with_name("malicious-receiver.py")
            backup = receiver.with_name("trusted-receiver.backup")
            replacement.write_bytes(
                replacement_source + b" " * (len(original) - len(replacement_source))
            )
            replacement.chmod(stat.S_IMODE(receiver.stat().st_mode))
            os.utime(
                replacement,
                ns=(receiver.stat().st_atime_ns, receiver.stat().st_mtime_ns),
            )
            completed = run_guard(
                bundle,
                report,
                test_environment={
                    "CODEX_REPORT_GUARD_TEST_MODE": "receiver-aba",
                    "CODEX_REPORT_GUARD_TEST_TARGET": str(receiver),
                    "CODEX_REPORT_GUARD_TEST_REPLACEMENT": str(replacement),
                    "CODEX_REPORT_GUARD_TEST_BACKUP": str(backup),
                },
            )
            self.assertEqual(receiver.read_bytes(), original)
            self.assertFalse(marker_path.exists())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["classification"], "accepted")

    def test_manifest_to_execution_control_replacement_is_rejected(self) -> None:
        report = valid_report()
        for relative in (
            "scripts/review_runtime/__init__.py",
            "scripts/review_runtime/catalog_bootstrap.py",
            "scripts/review_runtime/read_only_report_guard.py",
        ):
            with self.subTest(target=relative):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    bundle = copy_guard_bundle(root)
                    add_pre_execution_replacement_hook(bundle)
                    target = bundle / relative
                    original = target.read_bytes()
                    marker = root / f"{target.name}.executed"
                    malicious = (
                        "from pathlib import Path\n"
                        f"Path({str(marker)!r}).write_text('executed')\n"
                    ).encode("utf-8")
                    self.assertLess(len(malicious), len(original))
                    replacement = target.with_name(f"malicious-{target.name}")
                    backup = target.with_name(f"trusted-{target.name}.backup")
                    replacement.write_bytes(
                        malicious + b" " * (len(original) - len(malicious))
                    )
                    replacement.chmod(stat.S_IMODE(target.stat().st_mode))
                    completed = run_guard(
                        bundle,
                        report,
                        test_environment={
                            "CODEX_CONTROL_CAPTURE_TARGET": str(target),
                            "CODEX_CONTROL_CAPTURE_REPLACEMENT": str(replacement),
                            "CODEX_CONTROL_CAPTURE_BACKUP": str(backup),
                        },
                    )
                    self.assertEqual(target.read_bytes(), original)
                    self.assertFalse(marker.exists())
                self.assertNotEqual(completed.returncode, 0)
                self.assertNotIn(
                    b'"classification": "accepted"',
                    completed.stdout,
                )
                self.assertIn(b"digest does not match", completed.stderr)

    def test_terminal_content_and_access_drift_withhold_acceptance(self) -> None:
        report = valid_report()
        for mode, relative in (
            ("byte-drift", "scripts/read_only_pr_report.py"),
            (
                "byte-drift",
                "references/pr-readiness-read-only-report.schema.json",
            ),
            ("access-drift", "scripts/read_only_pr_report.py"),
            (
                "access-drift",
                "references/pr-readiness-read-only-report.schema.json",
            ),
        ):
            with self.subTest(mode=mode, target=relative):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    bundle = copy_guard_bundle(root)
                    add_receiver_test_hook(bundle)
                    target = bundle / relative
                    completed = run_guard(
                        bundle,
                        report,
                        test_environment={
                            "CODEX_REPORT_GUARD_TEST_MODE": mode,
                            "CODEX_REPORT_GUARD_TEST_TARGET": str(target),
                        },
                    )
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(
                    json.loads(completed.stdout)["classification"],
                    "rejected",
                )
                self.assertNotIn(
                    b'"classification": "accepted"',
                    completed.stdout,
                )

    def test_persistent_same_content_replacement_is_identity_drift(self) -> None:
        report = valid_report()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            bundle = copy_guard_bundle(root)
            add_receiver_test_hook(bundle)
            receiver = bundle / "scripts" / "read_only_pr_report.py"
            replacement = receiver.with_name("same-content-receiver.py")
            shutil.copy2(receiver, replacement)
            completed = run_guard(
                bundle,
                report,
                test_environment={
                    "CODEX_REPORT_GUARD_TEST_MODE": "persistent-replacement",
                    "CODEX_REPORT_GUARD_TEST_TARGET": str(receiver),
                    "CODEX_REPORT_GUARD_TEST_REPLACEMENT": str(replacement),
                },
            )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["classification"], "rejected")
        self.assertIn(b"parent entry identity changed", completed.stdout)

    def test_manifest_loader_and_artifact_bindings_are_exact(self) -> None:
        manifest = json.loads(CONTROL_MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["profile"], PROFILE)
        self.assertEqual(
            manifest["external_trust_root"],
            {
                "path": "scripts/named_lane_guard",
                "authority": "prior-trusted-canonical-bundle",
            },
        )
        self.assertEqual(
            manifest["loader"],
            {
                "path": "scripts/named_lane_guard",
                "profile_version": 1,
                "python_flags": ["-I", "-B", "-S"],
                "runtime": "scripts/review_runtime/read_only_report_guard.py",
                "runtime_version": 1,
                "schema_evaluator": "closed-draft-2020-12-v1",
            },
        )
        self.assertEqual(
            [
                (source["path"], source["role"])
                for source in manifest["control_sources"]
            ],
            [
                ("scripts/review_runtime/__init__.py", "runtime-package"),
                (
                    "scripts/review_runtime/catalog_bootstrap.py",
                    "binding-runtime",
                ),
                (
                    "scripts/review_runtime/read_only_report_guard.py",
                    "report-guard-runtime",
                ),
            ],
        )
        self.assertEqual(
            [
                (artifact["path"], artifact["role"])
                for artifact in manifest["artifacts"]
            ],
            [
                (
                    "references/pr-readiness-read-only-report.schema.json",
                    "schema",
                ),
                ("scripts/read_only_pr_report.py", "receiver"),
            ],
        )
        for artifact in (*manifest["control_sources"], *manifest["artifacts"]):
            self.assertEqual(
                artifact["sha256"],
                hashlib.sha256(
                    (SKILL_ROOT / artifact["path"]).read_bytes()
                ).hexdigest(),
            )
        guard = GUARD.read_text(encoding="utf-8")
        self.assertIn(
            hashlib.sha256(CONTROL_MANIFEST.read_bytes()).hexdigest(),
            guard,
        )
        self.assertNotIn("jsonschema", RUNTIME.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
