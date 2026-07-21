from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import claude_linux, claude_refresh_lock  # noqa: E402


_AMBIENT_TOOL_ENV_POISON = {
    "BASH_ENV": "/tmp/attacker-bash-env",
    "COMPILER_PATH": "/tmp/attacker-compiler",
    "CPATH": "/tmp/attacker-headers",
    "C_INCLUDE_PATH": "/tmp/attacker-c-headers",
    "ENV": "/tmp/attacker-sh-env",
    "GCC_EXEC_PREFIX": "/tmp/attacker-gcc/",
    "LD_LIBRARY_PATH": "/tmp/attacker-libraries",
    "LD_PRELOAD": "/tmp/attacker-preload.so",
    "LIBRARY_PATH": "/tmp/attacker-linker",
    "PATH": "/tmp/attacker-bin",
}


def _write_elf(
    path: pathlib.Path,
    *,
    arch: str = "x64",
    elf_type: int = 3,
    interpreter: str | None = "/lib64/ld-linux-x86-64.so.2",
    dynamic_tags: tuple[int, ...] | None = None,
    dynamic_load_count: int = 1,
    dynamic_vaddr_delta: int = 0,
    extra_load_segments: tuple[tuple[int, int, int, int], ...] = (),
) -> pathlib.Path:
    machine = {"x64": 62, "arm64": 183}[arch]
    if dynamic_tags is None:
        dynamic_load_count = 0
    if dynamic_load_count < 0:
        raise ValueError("dynamic_load_count must be non-negative")
    program_count = (
        (1 if interpreter is not None else 0)
        + (1 if dynamic_tags is not None else 0)
        + dynamic_load_count
        + len(extra_load_segments)
    )
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        header,
        16,
        elf_type,
        machine,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        program_count,
        0,
        0,
        0,
    )
    encoded_interpreter = (
        interpreter.encode("utf-8") + b"\x00" if interpreter is not None else b""
    )
    dynamic = bytearray()
    if dynamic_tags is not None:
        for tag in (*dynamic_tags, claude_linux.ELF_DYNAMIC_NULL):
            dynamic.extend(struct.pack("<qQ", tag, 0))

    data_offset = 64 + program_count * 56
    total_size = data_offset + len(encoded_interpreter) + len(dynamic)
    payload = bytearray(header)
    data = bytearray()
    for _index in range(dynamic_load_count):
        payload.extend(
            struct.pack(
                "<IIQQQQQQ",
                1,
                5,
                0,
                0,
                0,
                total_size,
                total_size,
                0x1000,
            )
        )
    for file_offset, virtual_address, file_size, memory_size in extra_load_segments:
        payload.extend(
            struct.pack(
                "<IIQQQQQQ",
                1,
                5,
                file_offset,
                virtual_address,
                0,
                file_size,
                memory_size,
                0x1000,
            )
        )
    if interpreter is not None:
        payload.extend(
            struct.pack(
                "<IIQQQQQQ",
                3,
                4,
                data_offset + len(data),
                0,
                0,
                len(encoded_interpreter),
                len(encoded_interpreter),
                1,
            )
        )
        data.extend(encoded_interpreter)
    if dynamic_tags is not None:
        dynamic_offset = data_offset + len(data)
        payload.extend(
            struct.pack(
                "<IIQQQQQQ",
                2,
                4,
                dynamic_offset,
                dynamic_offset + dynamic_vaddr_delta,
                0,
                len(dynamic),
                len(dynamic),
                8,
            )
        )
        data.extend(dynamic)
    payload.extend(data)
    path.write_bytes(payload)
    path.chmod(0o755)
    return path


def _capture(returncode: int = 0, stdout: bytes = b"", stderr: bytes = b""):
    return SimpleNamespace(
        returncode=returncode,
        stdout=bytearray(stdout),
        stderr=bytearray(stderr),
    )


def _linux_review_arguments() -> tuple[str, ...]:
    settings = json.dumps(
        {
            "disableAllHooks": True,
            "permissions": {
                "deny": list(claude_linux.CLAUDE_LINUX_FILE_TOOL_DENY_RULES)
            },
        },
        separators=(",", ":"),
    )
    return (
        "--safe-mode",
        "--print",
        "--permission-mode",
        claude_linux.CLAUDE_LINUX_REVIEW_PERMISSION_MODE,
        "--setting-sources",
        "",
        "--settings",
        settings,
        "--tools",
        claude_linux.CLAUDE_LINUX_REVIEW_VISIBLE_TOOLS,
        "--allowedTools",
        claude_linux.CLAUDE_LINUX_REVIEW_ALLOWED_TOOLS,
        "--disallowedTools",
        claude_linux.CLAUDE_LINUX_REVIEW_DISALLOWED_TOOLS,
    )


class _ForbiddenConnectProxy:
    def __init__(self, path: pathlib.Path) -> None:
        self.path = path
        self.requests: list[bytes] = []
        self.errors: list[str] = []
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "_ForbiddenConnectProxy":
        if len(os.fsencode(self.path)) >= 100:
            raise AssertionError(
                f"test proxy path exceeds AF_UNIX safety margin: {self.path}"
            )
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.path))
        self.path.chmod(0o600)
        listener.listen(8)
        listener.settimeout(0.1)
        self._listener = listener
        thread = threading.Thread(
            target=self._serve,
            name="claude-linux-test-proxy",
            daemon=False,
        )
        self._thread = thread
        thread.start()
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self._stop.set()
        if self._listener is not None:
            self._listener.close()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            if self._thread.is_alive():
                raise AssertionError("test proxy thread did not terminate")

    def _serve(self) -> None:
        assert self._listener is not None
        while not self._stop.is_set():
            try:
                connection, _address = self._listener.accept()
            except TimeoutError:
                continue
            except OSError as error:
                if not self._stop.is_set():
                    self.errors.append(f"proxy accept failed: {error}")
                return
            with connection:
                connection.settimeout(1.0)
                request = bytearray()
                try:
                    while len(request) < 4096 and b"\r\n\r\n" not in request:
                        chunk = connection.recv(4096 - len(request))
                        if not chunk:
                            break
                        request.extend(chunk)
                except TimeoutError:
                    if request:
                        self.errors.append("proxy request headers timed out")
                    continue
                if not request:
                    # The launcher readiness connection intentionally sends no data.
                    continue
                payload = bytes(request)
                self.requests.append(payload)
                if not payload.startswith(b"CONNECT example.invalid:443 HTTP/1.1\r\n"):
                    self.errors.append("proxy received an unexpected CONNECT target")
                    continue
                try:
                    connection.sendall(
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Content-Length: 0\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                except OSError as error:
                    self.errors.append(f"proxy response failed: {error}")


class HostDetectionTest(unittest.TestCase):
    def test_detects_native_linux_and_supported_architecture(self) -> None:
        host = claude_linux.detect_host(
            system="Linux",
            machine="x86_64",
            kernel_release="6.8.0-generic",
            proc_version="#1 SMP",
            env={},
            run_wsl_exists=False,
            binfmt_wslinterop_exists=False,
        )

        self.assertEqual(host.kind, claude_linux.LinuxHostKind.LINUX)
        self.assertEqual(host.arch, "x64")
        self.assertTrue(host.supported)

    def test_detects_wsl2_and_wsl1_separately(self) -> None:
        wsl2 = claude_linux.detect_host(
            system="Linux",
            machine="aarch64",
            kernel_release="5.15.153.1-microsoft-standard-WSL2",
            proc_version="Microsoft",
            env={},
            run_wsl_exists=False,
            binfmt_wslinterop_exists=False,
        )
        wsl1 = claude_linux.detect_host(
            system="Linux",
            machine="x86_64",
            kernel_release="4.4.0-19041-Microsoft",
            proc_version="Microsoft",
            env={"WSL_DISTRO_NAME": "Ubuntu"},
            run_wsl_exists=False,
            binfmt_wslinterop_exists=True,
        )

        self.assertEqual(wsl2.kind, claude_linux.LinuxHostKind.WSL2)
        self.assertEqual(wsl2.arch, "arm64")
        self.assertEqual(wsl1.kind, claude_linux.LinuxHostKind.WSL1)
        with self.assertRaisesRegex(claude_linux.LinuxUnsupportedHost, "WSL1"):
            claude_linux.require_supported_host(wsl1)

    def test_custom_kernel_runtime_markers_prove_only_wsl_presence(self) -> None:
        run_directory = claude_linux.detect_host(
            system="Linux",
            machine="x86_64",
            kernel_release="6.6.36-custom-acme",
            proc_version="#1 SMP PREEMPT_DYNAMIC",
            env={"WSL_DISTRO_NAME": "Ubuntu"},
            run_wsl_exists=True,
            binfmt_wslinterop_exists=True,
        )
        interop_endpoint = claude_linux.detect_host(
            system="Linux",
            machine="x86_64",
            kernel_release="6.6.36-custom-acme",
            proc_version="#1 SMP PREEMPT_DYNAMIC",
            env={
                "WSL_DISTRO_NAME": "Ubuntu",
                "WSL_INTEROP": "/run/WSL/42_interop",
            },
            run_wsl_exists=False,
            interop_path_exists=True,
            binfmt_wslinterop_exists=True,
        )

        self.assertEqual(run_directory.kind, claude_linux.LinuxHostKind.WSL1)
        self.assertEqual(interop_endpoint.kind, claude_linux.LinuxHostKind.WSL1)

    def test_wsl1_with_real_interop_markers_remains_wsl1(self) -> None:
        host = claude_linux.detect_host(
            system="Linux",
            machine="x86_64",
            kernel_release="4.4.0-19041-Microsoft",
            proc_version="Microsoft",
            env={
                "WSL_DISTRO_NAME": "Ubuntu",
                "WSL_INTEROP": "/run/WSL/42_interop",
            },
            run_wsl_exists=True,
            interop_path_exists=True,
            binfmt_wslinterop_exists=True,
        )

        self.assertEqual(host.kind, claude_linux.LinuxHostKind.WSL1)

    def test_ambiguous_or_spoofed_wsl_environment_fails_closed_as_wsl1(self) -> None:
        ambiguous = claude_linux.detect_host(
            system="Linux",
            machine="x86_64",
            kernel_release="6.8.0-generic",
            proc_version="#1 SMP",
            env={
                "WSL_DISTRO_NAME": "spoofed",
                "WSL_INTEROP": "/tmp/not-a-wsl-interop-endpoint",
            },
            run_wsl_exists=False,
            interop_path_exists=True,
            binfmt_wslinterop_exists=False,
        )
        binfmt_only = claude_linux.detect_host(
            system="Linux",
            machine="x86_64",
            kernel_release="6.8.0-generic",
            proc_version="#1 SMP",
            env={},
            run_wsl_exists=False,
            binfmt_wslinterop_exists=True,
        )
        invalid_interop_only = claude_linux.detect_host(
            system="Linux",
            machine="x86_64",
            kernel_release="6.8.0-generic",
            proc_version="#1 SMP",
            env={"WSL_INTEROP": "/tmp/not-a-wsl-interop-endpoint"},
            run_wsl_exists=False,
            interop_path_exists=False,
            binfmt_wslinterop_exists=False,
        )
        generic_microsoft_kernel_only = claude_linux.detect_host(
            system="Linux",
            machine="x86_64",
            kernel_release="4.4.0-19041-Microsoft",
            proc_version="#1 SMP",
            env={},
            run_wsl_exists=False,
            binfmt_wslinterop_exists=False,
        )

        self.assertEqual(ambiguous.kind, claude_linux.LinuxHostKind.WSL1)
        self.assertEqual(binfmt_only.kind, claude_linux.LinuxHostKind.WSL1)
        self.assertEqual(invalid_interop_only.kind, claude_linux.LinuxHostKind.WSL1)
        self.assertEqual(
            generic_microsoft_kernel_only.kind,
            claude_linux.LinuxHostKind.WSL1,
        )

    def test_rejects_native_windows_with_wsl2_guidance(self) -> None:
        host = claude_linux.detect_host(system="Windows", machine="AMD64")

        self.assertEqual(host.kind, claude_linux.LinuxHostKind.NATIVE_WINDOWS)
        with self.assertRaisesRegex(claude_linux.LinuxUnsupportedHost, "WSL2"):
            claude_linux.require_supported_host(host)

    def test_rejects_wsl_windows_drive_runtime_path(self) -> None:
        host = claude_linux.LinuxHost(
            claude_linux.LinuxHostKind.WSL2, "x64", "microsoft-standard-WSL2"
        )

        with (
            mock.patch.object(claude_linux, "_read_mountinfo") as read_mountinfo,
            self.assertRaisesRegex(claude_linux.LinuxRuntimeUnsafe, "Windows drive"),
        ):
            claude_linux.reject_wsl_windows_path(
                pathlib.Path("/mnt/c/Users/user/claude"), host
            )

        read_mountinfo.assert_not_called()


class WslWindowsFilesystemProvenanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.wsl2 = claude_linux.LinuxHost(
            claude_linux.LinuxHostKind.WSL2,
            "x64",
            "microsoft-standard-WSL2",
        )

    @staticmethod
    def _root_mount() -> str:
        return "24 1 0:22 / / rw,relatime - ext4 /dev/sda rw"

    @staticmethod
    def _mount(
        mount_point: pathlib.Path | str,
        *,
        file_system: str,
        source: str,
        super_options: str = "rw",
        mount_id: int = 52,
    ) -> str:
        return (
            f"{mount_id} 24 0:41 / {mount_point} rw,relatime - "
            f"{file_system} {source} {super_options}"
        )

    def test_rejects_custom_automount_root_and_bind_alias(self) -> None:
        custom_automount = "\n".join(
            (
                self._root_mount(),
                self._mount(
                    "/windows/c",
                    file_system="9p",
                    source=r"C:\134",
                    super_options=r"rw,aname=drvfs;path=C:\134",
                ),
            )
        )
        bind_alias = "\n".join(
            (
                self._root_mount(),
                self._mount(
                    "/home/reviewer/windows-alias",
                    file_system="9p",
                    source="drvfs",
                    super_options="rw,aname=drvfs",
                ),
            )
        )

        with self.assertRaisesRegex(claude_linux.LinuxRuntimeUnsafe, "filesystem"):
            claude_linux.reject_wsl_windows_path(
                pathlib.Path("/windows/c/Users/reviewer/claude"),
                self.wsl2,
                mountinfo_text=custom_automount,
            )
        with self.assertRaisesRegex(claude_linux.LinuxRuntimeUnsafe, "filesystem"):
            claude_linux.reject_wsl_windows_path(
                pathlib.Path("/home/reviewer/windows-alias/claude"),
                self.wsl2,
                mountinfo_text=bind_alias,
            )

    def test_resolved_symlink_alias_cannot_hide_drvfs_mount(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            windows_root = root / "windows-volume"
            windows_root.mkdir()
            alias = root / "apparently-linux"
            alias.symlink_to(windows_root, target_is_directory=True)
            mountinfo = "\n".join(
                (
                    self._root_mount(),
                    self._mount(
                        windows_root,
                        file_system="9p",
                        source=r"C:\134",
                        super_options=r"rw,aname=drvfs;path=C:\134",
                    ),
                )
            )

            with self.assertRaisesRegex(claude_linux.LinuxRuntimeUnsafe, "filesystem"):
                claude_linux.reject_wsl_windows_path(
                    alias / "claude",
                    self.wsl2,
                    mountinfo_text=mountinfo,
                )

    def test_accepts_proven_local_native_filesystems(self) -> None:
        cases = (
            ("/home/reviewer/project", self._root_mount()),
            (
                "/run/review/project",
                "\n".join(
                    (
                        self._root_mount(),
                        self._mount("/run/review", file_system="tmpfs", source="tmpfs"),
                    )
                ),
            ),
        )

        for path, mountinfo in cases:
            with self.subTest(path=path):
                claude_linux.reject_wsl_windows_path(
                    pathlib.Path(path), self.wsl2, mountinfo_text=mountinfo
                )

    def test_unproven_layered_shared_and_loop_filesystems_are_inconclusive(
        self,
    ) -> None:
        cases = (
            ("overlay", "overlay", "rw,lowerdir=/mnt/c/base,upperdir=/upper"),
            ("fuse.bindfs", "bindfs", "rw"),
            ("9p", "linux-share", "rw"),
            ("virtiofs", "linux-share", "rw"),
            ("ext4", "/dev/loop0", "rw"),
        )

        for file_system, source, super_options in cases:
            with (
                self.subTest(file_system=file_system, source=source),
                self.assertRaisesRegex(
                    claude_linux.LinuxRuntimeInspectionInconclusive,
                    "cannot prove.*local native Linux filesystem",
                ),
            ):
                claude_linux.reject_wsl_windows_path(
                    pathlib.Path("/review-state/runtime"),
                    self.wsl2,
                    mountinfo_text="\n".join(
                        (
                            self._root_mount(),
                            self._mount(
                                "/review-state",
                                file_system=file_system,
                                source=source,
                                super_options=super_options,
                            ),
                        )
                    ),
                )

    def test_ext4_requires_wsl_sd_block_source(self) -> None:
        accepted = self._mount(
            "/review-state",
            file_system="ext4",
            source="/dev/sdb1",
        )
        claude_linux.reject_wsl_windows_path(
            pathlib.Path("/review-state/runtime"),
            self.wsl2,
            mountinfo_text="\n".join((self._root_mount(), accepted)),
        )

        for source in (
            "/dev/dm-0",
            "/dev/mapper/review",
            "/dev/nbd0",
            "/dev/md0",
            "UUID=01234567-89ab-cdef-0123-456789abcdef",
            "LABEL=review",
            "relative-device",
        ):
            with (
                self.subTest(source=source),
                self.assertRaises(claude_linux.LinuxRuntimeInspectionInconclusive),
            ):
                claude_linux.reject_wsl_windows_path(
                    pathlib.Path("/review-state/runtime"),
                    self.wsl2,
                    mountinfo_text="\n".join(
                        (
                            self._root_mount(),
                            self._mount(
                                "/review-state",
                                file_system="ext4",
                                source=source,
                            ),
                        )
                    ),
                )

    def test_mountinfo_decodes_option_escapes_once(self) -> None:
        mountinfo = "\n".join(
            (
                self._root_mount(),
                self._mount(
                    "/unrelated-overlay",
                    file_system="overlay",
                    source="overlay",
                    super_options=r"rw,lowerdir=/layers/a\054b\072c\134054",
                ),
            )
        )

        entries = claude_linux._parse_mountinfo(mountinfo)

        self.assertEqual(
            entries[1].super_options,
            r"rw,lowerdir=/layers/a,b:c\054",
        )
        claude_linux.reject_wsl_windows_path(
            pathlib.Path("/home/reviewer/project"),
            self.wsl2,
            mountinfo_text=mountinfo,
        )

    def test_nsfs_namespace_root_coexists_with_native_and_wsl_mounts(self) -> None:
        nsfs = (
            "71 24 0:65 net:[4026531840] /run/netns/review rw,relatime - nsfs nsfs rw"
        )
        child_nsfs = (
            "72 24 0:66 time_for_children:[4026531834] "
            "/run/time-ns/review rw,relatime - nsfs nsfs rw"
        )
        mountinfo = "\n".join((self._root_mount(), nsfs, child_nsfs))
        native = claude_linux.LinuxHost(
            claude_linux.LinuxHostKind.LINUX,
            "x64",
            "6.8.0-generic",
        )

        entries = claude_linux._parse_mountinfo(mountinfo)

        self.assertEqual(entries[1].root, "net:[4026531840]")
        self.assertEqual(entries[2].root, "time_for_children:[4026531834]")
        for host in (native, self.wsl2):
            with self.subTest(host=host.kind.value):
                claude_linux.reject_wsl_windows_path(
                    pathlib.Path("/home/reviewer/project"),
                    host,
                    mountinfo_text=mountinfo,
                )

    def test_non_nsfs_opaque_root_fails_closed(self) -> None:
        opaque_ext4 = (
            "71 24 0:65 net:[4026531840] /unrelated rw,relatime - ext4 /dev/sdb rw"
        )

        with self.assertRaisesRegex(
            claude_linux.LinuxRuntimeInspectionInconclusive,
            "non-canonical root",
        ):
            claude_linux.reject_wsl_windows_path(
                pathlib.Path("/home/reviewer/project"),
                self.wsl2,
                mountinfo_text="\n".join((self._root_mount(), opaque_ext4)),
            )

    def test_malformed_nsfs_namespace_roots_fail_closed(self) -> None:
        malformed_roots = (
            "net:[]",
            "net:[0123]",
            "net:[18446744073709551616]",
            "Net:[4026531840]",
            "net/child:[4026531840]",
        )

        for root in malformed_roots:
            mount = f"71 24 0:65 {root} /run/netns/review rw,relatime - nsfs nsfs rw"
            with (
                self.subTest(root=root),
                self.assertRaisesRegex(
                    claude_linux.LinuxRuntimeInspectionInconclusive,
                    "non-canonical root",
                ),
            ):
                claude_linux.reject_wsl_windows_path(
                    pathlib.Path("/home/reviewer/project"),
                    self.wsl2,
                    mountinfo_text="\n".join((self._root_mount(), mount)),
                )

    def test_same_depth_mounts_preserve_windows_before_unknown_tristate(self) -> None:
        windows = self._mount(
            "/review-state",
            file_system="9p",
            source="drvfs",
            super_options="rw,aname=drvfs",
            mount_id=52,
        )
        unknown = self._mount(
            "/review-state",
            file_system="overlay",
            source="overlay",
            super_options="rw,lowerdir=/lower",
            mount_id=53,
        )
        native = self._mount(
            "/review-state",
            file_system="ext4",
            source="/dev/sdb",
            mount_id=54,
        )

        with self.assertRaises(claude_linux.LinuxRuntimeUnsafe):
            claude_linux.reject_wsl_windows_path(
                pathlib.Path("/review-state/runtime"),
                self.wsl2,
                mountinfo_text="\n".join((self._root_mount(), windows, unknown)),
            )
        with self.assertRaises(claude_linux.LinuxRuntimeInspectionInconclusive):
            claude_linux.reject_wsl_windows_path(
                pathlib.Path("/review-state/runtime"),
                self.wsl2,
                mountinfo_text="\n".join((self._root_mount(), native, unknown)),
            )

    def test_rejects_virtiofs_only_with_explicit_windows_provenance(self) -> None:
        mountinfo = "\n".join(
            (
                self._root_mount(),
                self._mount(
                    "/windows/d",
                    file_system="virtiofs",
                    source=r"D:\134",
                ),
            )
        )

        with self.assertRaisesRegex(claude_linux.LinuxRuntimeUnsafe, "filesystem"):
            claude_linux.reject_wsl_windows_path(
                pathlib.Path("/windows/d/review"),
                self.wsl2,
                mountinfo_text=mountinfo,
            )

    def test_batch_rejects_drvfs_ancestor_below_linux_submount(self) -> None:
        parent = pathlib.Path("/review-state")
        candidate = parent / "gpg-tmp"
        mountinfo = "\n".join(
            (
                self._root_mount(),
                self._mount(
                    parent,
                    file_system="9p",
                    source="drvfs",
                    super_options="rw,aname=drvfs",
                    mount_id=52,
                ),
                self._mount(
                    candidate,
                    file_system="ext4",
                    source="/dev/sdb",
                    mount_id=53,
                ),
            )
        )

        with (
            mock.patch.object(
                claude_linux,
                "_read_mountinfo",
                return_value=mountinfo,
            ) as read_mountinfo,
            self.assertRaisesRegex(
                claude_linux.LinuxRuntimeUnsafe,
                "filesystem",
            ),
        ):
            claude_linux.reject_wsl_windows_paths(
                (candidate, parent),
                self.wsl2,
            )

        read_mountinfo.assert_called_once()

    def test_fails_closed_for_malformed_oversized_or_unavailable_mountinfo(
        self,
    ) -> None:
        malformed = "24 1 0:22 / / rw,relatime ext4 /dev/sda rw"
        oversized = "x" * (claude_linux.MOUNTINFO_LIMIT_BYTES + 1)
        invalid_escape = self._mount(
            "/review-state",
            file_system="overlay",
            source="overlay",
            super_options=r"rw,lowerdir=/layers/a\777b",
        )

        for payload in (malformed, oversized, invalid_escape, ""):
            with (
                self.subTest(payload_length=len(payload)),
                self.assertRaisesRegex(
                    claude_linux.LinuxRuntimeInspectionInconclusive,
                    "mountinfo",
                ),
            ):
                claude_linux.reject_wsl_windows_path(
                    pathlib.Path("/home/reviewer/project"),
                    self.wsl2,
                    mountinfo_text=payload,
                )
        with tempfile.TemporaryDirectory() as temporary:
            unavailable = pathlib.Path(temporary) / "missing-mountinfo"
            with self.assertRaisesRegex(
                claude_linux.LinuxRuntimeInspectionInconclusive,
                "cannot read Linux mountinfo",
            ):
                claude_linux.reject_wsl_windows_path(
                    pathlib.Path("/home/reviewer/project"),
                    self.wsl2,
                    mountinfo_path=unavailable,
                )

    def test_native_linux_still_rejects_positive_windows_mount_provenance(
        self,
    ) -> None:
        native = claude_linux.LinuxHost(
            claude_linux.LinuxHostKind.LINUX, "x64", "6.8.0-generic"
        )
        windows_mount = "\n".join(
            (
                self._root_mount(),
                self._mount(
                    "/review-state",
                    file_system="9p",
                    source="drvfs",
                    super_options="rw,aname=drvfs",
                ),
            )
        )
        native_overlay = "\n".join(
            (
                self._root_mount(),
                self._mount(
                    "/review-state",
                    file_system="overlay",
                    source="overlay",
                    super_options="rw,lowerdir=/lower,upperdir=/upper",
                ),
            )
        )

        with self.assertRaisesRegex(claude_linux.LinuxRuntimeUnsafe, "filesystem"):
            claude_linux.reject_wsl_windows_path(
                pathlib.Path("/review-state/runtime"),
                native,
                mountinfo_text=windows_mount,
            )
        claude_linux.reject_wsl_windows_path(
            pathlib.Path("/review-state/runtime"),
            native,
            mountinfo_text=native_overlay,
        )

    def test_markerless_guest_linux_classification_still_rejects_drvfs(
        self,
    ) -> None:
        markerless = claude_linux.detect_host(
            system="Linux",
            machine="x86_64",
            kernel_release="6.6.36-custom-acme",
            proc_version="#1 SMP PREEMPT_DYNAMIC",
            env={},
            run_wsl_exists=False,
            interop_path_exists=False,
            binfmt_wslinterop_exists=False,
        )
        windows_mount = "\n".join(
            (
                self._root_mount(),
                self._mount(
                    "/review-state",
                    file_system="9p",
                    source="drvfs",
                    super_options="rw,aname=drvfs",
                ),
            )
        )

        self.assertEqual(markerless.kind, claude_linux.LinuxHostKind.LINUX)
        with self.assertRaises(claude_linux.LinuxRuntimeUnsafe):
            claude_linux.reject_wsl_windows_path(
                pathlib.Path("/review-state/runtime"),
                markerless,
                mountinfo_text=windows_mount,
            )

    def test_native_linux_local_mnt_drive_name_uses_mount_provenance(
        self,
    ) -> None:
        native = claude_linux.LinuxHost(
            claude_linux.LinuxHostKind.LINUX, "x64", "6.8.0-generic"
        )
        local_mount = "\n".join(
            (
                self._root_mount(),
                self._mount(
                    "/mnt/c",
                    file_system="ext4",
                    source="/dev/sdz1",
                ),
            )
        )

        claude_linux.reject_wsl_windows_path(
            pathlib.Path("/mnt/c/reviewer/project"),
            native,
            mountinfo_text=local_mount,
        )


class ElfInspectionTest(unittest.TestCase):
    def test_maps_glibc_and_musl_x64_and_arm64_platform_keys(self) -> None:
        cases = (
            ("x64", "/lib64/ld-linux-x86-64.so.2", "linux-x64"),
            ("arm64", "/lib/ld-linux-aarch64.so.1", "linux-arm64"),
            ("x64", "/lib/ld-musl-x86_64.so.1", "linux-x64-musl"),
            ("arm64", "/lib/ld-musl-aarch64.so.1", "linux-arm64-musl"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for index, (arch, interpreter, expected) in enumerate(cases):
                with self.subTest(expected=expected):
                    path = _write_elf(
                        root / f"claude-{index}",
                        arch=arch,
                        interpreter=interpreter,
                    )

                    info = claude_linux.inspect_elf(path)

                    self.assertEqual(info.arch, arch)
                    self.assertEqual(info.manifest_platform_key, expected)

    def test_rejects_script_wrapper_and_static_unknown_libc(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            wrapper = root / "claude"
            wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            wrapper.chmod(0o755)
            static_elf = _write_elf(root / "static", interpreter=None)

            with self.assertRaisesRegex(
                claude_linux.LinuxRuntimeError,
                "truncated ELF header",
            ):
                claude_linux.inspect_elf(wrapper)
            with self.assertRaisesRegex(claude_linux.LinuxRuntimeError, "libc"):
                _ = claude_linux.inspect_elf(static_elf).manifest_platform_key

    def test_rejects_architecture_mismatch(self) -> None:
        host = claude_linux.LinuxHost(claude_linux.LinuxHostKind.LINUX, "arm64", "6.8")
        with tempfile.TemporaryDirectory() as temporary:
            path = _write_elf(pathlib.Path(temporary) / "claude", arch="x64")

            with self.assertRaisesRegex(
                claude_linux.LinuxRuntimeError, "does not match"
            ):
                claude_linux.validate_claude_executable(path, host)

    def test_dynamic_segment_requires_a_unique_covering_load(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for label, load_count in (("missing", 0), ("ambiguous", 2)):
                with (
                    self.subTest(label=label),
                    self.assertRaisesRegex(
                        claude_linux.LinuxRuntimeError,
                        "exactly one covering PT_LOAD",
                    ),
                ):
                    claude_linux.inspect_elf(
                        _write_elf(
                            root / label,
                            interpreter=None,
                            dynamic_tags=(),
                            dynamic_load_count=load_count,
                        )
                    )

    def test_dynamic_segment_requires_file_backing_and_bounded_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            not_file_backed = _write_elf(
                root / "not-file-backed",
                interpreter=None,
                dynamic_tags=(),
            )
            payload = bytearray(not_file_backed.read_bytes())
            dynamic_size = claude_linux.ELF_DYNAMIC_ENTRY_BYTES
            struct.pack_into(
                "<Q",
                payload,
                claude_linux.ELF_HEADER_SIZE + 32,
                len(payload) - dynamic_size,
            )
            not_file_backed.write_bytes(payload)
            with self.assertRaisesRegex(
                claude_linux.LinuxRuntimeError,
                "not fully file-backed",
            ):
                claude_linux.inspect_elf(not_file_backed)

            overflowing = _write_elf(
                root / "overflowing",
                interpreter=None,
                dynamic_tags=(),
            )
            payload = bytearray(overflowing.read_bytes())
            dynamic_header = claude_linux.ELF_HEADER_SIZE + 56
            struct.pack_into("<Q", payload, dynamic_header + 16, 2**64 - 1)
            overflowing.write_bytes(payload)
            with self.assertRaisesRegex(
                claude_linux.LinuxRuntimeError,
                "range overflows",
            ):
                claude_linux.inspect_elf(overflowing)

    def test_rejects_incongruent_load_offset_for_host_page_size(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = _write_elf(
                pathlib.Path(temporary) / "incongruent",
                interpreter=None,
                dynamic_tags=(),
            )
            payload = bytearray(path.read_bytes())
            struct.pack_into(
                "<Q",
                payload,
                claude_linux.ELF_HEADER_SIZE + 16,
                1,
            )
            path.write_bytes(payload)

            with self.assertRaisesRegex(
                claude_linux.LinuxRuntimeError,
                "not congruent at the host page size",
            ):
                claude_linux.inspect_elf(path)

    def test_rejects_invalid_host_page_size(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = _write_elf(pathlib.Path(temporary) / "program")

            with (
                mock.patch.object(claude_linux.mmap, "PAGESIZE", 3),
                self.assertRaisesRegex(
                    claude_linux.LinuxRuntimeInspectionInconclusive,
                    "bounded power of two",
                ),
            ):
                claude_linux.inspect_elf(path)

    def test_elf_descriptor_io_failures_are_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = _write_elf(pathlib.Path(temporary) / "claude")
            real_close = os.close

            def close_then_fail(fd: int) -> None:
                real_close(fd)
                raise OSError("close raced")

            cases = (
                (
                    "open",
                    mock.patch.object(
                        claude_linux.os,
                        "open",
                        side_effect=OSError("open raced"),
                    ),
                ),
                (
                    "fstat",
                    mock.patch.object(
                        claude_linux.os,
                        "fstat",
                        side_effect=OSError("fstat raced"),
                    ),
                ),
                (
                    "pread",
                    mock.patch.object(
                        claude_linux.os,
                        "pread",
                        side_effect=OSError("pread raced"),
                    ),
                ),
                (
                    "close",
                    mock.patch.object(
                        claude_linux.os,
                        "close",
                        side_effect=close_then_fail,
                    ),
                ),
            )

            for operation, failure in cases:
                with (
                    self.subTest(operation=operation),
                    failure,
                    self.assertRaisesRegex(
                        claude_linux.LinuxRuntimeInspectionInconclusive,
                        operation,
                    ),
                ):
                    claude_linux.inspect_elf(path)

    def test_elf_close_failure_does_not_replace_primary_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = _write_elf(pathlib.Path(temporary) / "claude")
            real_close = os.close

            def close_then_fail(fd: int) -> None:
                real_close(fd)
                raise OSError("close raced")

            interrupt = KeyboardInterrupt("inspection cancelled")
            cases = (
                (
                    "format",
                    mock.patch.object(
                        claude_linux.os,
                        "pread",
                        return_value=(
                            b"not-elf" + b"\x00" * (claude_linux.ELF_HEADER_SIZE - 7)
                        ),
                    ),
                    claude_linux.LinuxRuntimeError,
                    "native ELF",
                    None,
                ),
                (
                    "interrupt",
                    mock.patch.object(
                        claude_linux.os,
                        "fstat",
                        side_effect=interrupt,
                    ),
                    KeyboardInterrupt,
                    "inspection cancelled",
                    interrupt,
                ),
            )

            for operation, primary, error_type, message, expected in cases:
                with (
                    self.subTest(operation=operation),
                    primary,
                    mock.patch.object(
                        claude_linux.os,
                        "close",
                        side_effect=close_then_fail,
                    ),
                    self.assertRaisesRegex(error_type, message) as raised,
                ):
                    claude_linux.inspect_elf(path)

                if expected is not None:
                    self.assertIs(raised.exception, expected)
                notes = getattr(raised.exception, "__notes__", ())
                if notes:
                    self.assertTrue(
                        any("ELF descriptor cleanup" in note for note in notes)
                    )
                else:
                    diagnostic = raised.exception.__cause__
                    self.assertIsInstance(
                        diagnostic,
                        claude_linux.LinuxRuntimeInspectionCleanupDiagnostic,
                    )
                    assert diagnostic is not None
                    self.assertIn("ELF descriptor cleanup", str(diagnostic))

    def test_elf_short_read_and_metadata_race_are_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            path = _write_elf(root / "claude")

            with (
                mock.patch.object(
                    claude_linux.os,
                    "pread",
                    return_value=b"not-elf",
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxRuntimeInspectionInconclusive,
                    "short read",
                ),
            ):
                claude_linux.inspect_elf(path)

            before = path.stat()
            after = SimpleNamespace(
                **{
                    field: getattr(before, field)
                    for field in claude_linux._ELF_STABLE_METADATA_FIELDS
                }
            )
            after.st_mtime_ns += 1
            with (
                mock.patch.object(
                    claude_linux.os,
                    "fstat",
                    side_effect=(before, after),
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxRuntimeInspectionInconclusive,
                    "changed during inspection",
                ),
            ):
                claude_linux.inspect_elf(path)

            truncated = root / "truncated"
            truncated.write_bytes(b"\x7fELF")
            with self.assertRaisesRegex(
                claude_linux.LinuxRuntimeError,
                "truncated ELF header",
            ):
                claude_linux.inspect_elf(truncated)

            oversized_offset = _write_elf(root / "oversized-offset")
            payload = bytearray(oversized_offset.read_bytes())
            struct.pack_into(
                "<Q",
                payload,
                claude_linux.ELF_HEADER_SIZE + 8,
                2**64 - 1,
            )
            oversized_offset.write_bytes(payload)
            with self.assertRaisesRegex(
                claude_linux.LinuxRuntimeError,
                "truncated ELF interpreter metadata",
            ):
                claude_linux.inspect_elf(oversized_offset)


class ToolchainDiscoveryTest(unittest.TestCase):
    def test_discovers_native_tools_and_runs_real_shape_bwrap_probe(self) -> None:
        host = claude_linux.LinuxHost(claude_linux.LinuxHostKind.LINUX, "x64", "6.8")
        calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

        def runner(argv, **kwargs):
            command = tuple(argv)
            calls.append((command, kwargs["env"]))
            name = pathlib.Path(command[0]).name
            if name == "bwrap" and "--unshare-net" in command:
                return _capture(stdout=b"ripgrep 14.1.0\n")
            outputs = {
                "bwrap": b"bubblewrap 0.11.0\n",
                "socat": b"socat version 1.8.0\n",
                "rg": b"ripgrep 14.1.0\n",
                "cc": b"gcc (GCC) 14.1.0\n",
            }
            return _capture(stdout=outputs[name])

        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            candidates = {}
            for name in ("bwrap", "socat", "rg", "cc"):
                candidates[name] = (_write_elf(root / name),)

            with mock.patch.dict(os.environ, _AMBIENT_TOOL_ENV_POISON, clear=False):
                toolchain = claude_linux.discover_native_toolchain(
                    host,
                    runner=runner,
                    candidates=candidates,
                    trusted_roots=(root,),
                    trusted_owner_uids=frozenset({os.getuid()}),
                )

        self.assertEqual(toolchain.bwrap.name, "bwrap")
        expected_env = claude_linux.fixed_host_tool_environment()
        self.assertTrue(calls)
        for _command, environment in calls:
            self.assertEqual(environment, expected_env)
            self.assertEqual(environment["PATH"], "/usr/bin:/bin")
            for key in _AMBIENT_TOOL_ENV_POISON.keys() - {"PATH"}:
                self.assertNotIn(key, environment)
        bwrap_probe = next(call for call, _env in calls if "--unshare-net" in call)
        for required in (
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-cgroup",
            "--disable-userns",
        ):
            self.assertIn(required, bwrap_probe)
        self.assertIn(("--cap-drop", "ALL"), tuple(zip(bwrap_probe, bwrap_probe[1:])))

    def test_compiler_and_ldd_probes_ignore_ambient_environment(self) -> None:
        host = claude_linux.LinuxHost(claude_linux.LinuxHostKind.LINUX, "x64", "6.8")
        toolchain = claude_linux.NativeToolchain(
            pathlib.Path("/usr/bin/bwrap"),
            pathlib.Path("/usr/bin/socat"),
            pathlib.Path("/usr/bin/rg"),
            pathlib.Path("/usr/bin/cc"),
        )
        calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

        def runner(argv, **kwargs):
            command = tuple(argv)
            calls.append((command, kwargs["env"]))
            if command[0] == str(toolchain.cc):
                _write_elf(pathlib.Path(command[-1]))
                return _capture()
            return _capture(stdout=b"statically linked\n")

        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            source = root / "launcher.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            ldd = root / "ldd"
            ldd.write_text("test-only\n", encoding="utf-8")
            ldd.chmod(0o500)
            with mock.patch.dict(os.environ, _AMBIENT_TOOL_ENV_POISON, clear=False):
                launcher = claude_linux.compile_launcher(
                    host,
                    toolchain,
                    root / "launcher",
                    source_path=source,
                    runner=runner,
                )
                libraries = claude_linux.collect_runtime_libraries(
                    host,
                    (launcher,),
                    runner=runner,
                    ldd_path=ldd,
                    ldd_trusted_roots=(root,),
                    trusted_owner_uids=frozenset({0, os.getuid()}),
                )

        self.assertEqual(libraries, ())
        self.assertEqual(
            tuple(pathlib.Path(command[0]).name for command, _env in calls),
            ("cc", "ldd"),
        )
        expected_env = claude_linux.fixed_host_tool_environment()
        for _command, environment in calls:
            self.assertEqual(environment, expected_env)
            for key in _AMBIENT_TOOL_ENV_POISON.keys() - {"PATH"}:
                self.assertNotIn(key, environment)

    def test_fails_closed_when_bwrap_namespace_probe_fails(self) -> None:
        host = claude_linux.LinuxHost(
            claude_linux.LinuxHostKind.WSL2, "x64", "microsoft-standard-WSL2"
        )
        tools = claude_linux.NativeToolchain(
            pathlib.Path("/usr/bin/bwrap"),
            pathlib.Path("/usr/bin/socat"),
            pathlib.Path("/usr/bin/rg"),
            pathlib.Path("/usr/bin/cc"),
        )

        with self.assertRaisesRegex(
            claude_linux.LinuxIsolationUnavailable, "cannot create"
        ):
            claude_linux.probe_bwrap(
                host,
                tools,
                runner=lambda *_args, **_kwargs: _capture(
                    returncode=1, stderr=b"user namespaces disabled"
                ),
            )


class RuntimeLibraryTrustTest(unittest.TestCase):
    def setUp(self) -> None:
        self.host = claude_linux.LinuxHost(
            claude_linux.LinuxHostKind.LINUX, "x64", "6.8"
        )
        self.trusted_owners = frozenset({0, os.getuid()})

    def _glibc_loader_fixture(
        self,
        root: pathlib.Path,
        *,
        arch: str = "x64",
        interpreter: str | None = None,
        dynamic_tags: tuple[int, ...] | None = None,
    ) -> claude_linux.HostRuntimeDependency:
        loader_path = _write_elf(
            root / f"test-glibc-loader-{arch}",
            arch=arch,
            interpreter=interpreter,
            dynamic_tags=dynamic_tags,
        )
        destination = claude_linux._CANONICAL_GLIBC_LOADERS[arch]
        return claude_linux._capture_host_runtime_dependency(
            loader_path,
            destination,
            trusted_owner_uids=self.trusted_owners,
        )

    @staticmethod
    def _glibc_runner(
        *,
        list_stdout: bytes = b"statically linked\n",
        list_returncode: int = 0,
        list_stderr: bytes = b"",
    ):
        def runner(argv, **_kwargs):  # type: ignore[no-untyped-def]
            command = tuple(argv)
            if len(command) >= 2 and command[1] == "--version":
                return _capture(
                    stdout=(
                        b"ld.so (Ubuntu GLIBC 2.39-0ubuntu8.7) "
                        b"stable release version 2.39.\n"
                    )
                )
            if len(command) >= 2 and command[1] == "--list":
                return _capture(
                    returncode=list_returncode,
                    stdout=list_stdout,
                    stderr=list_stderr,
                )
            raise AssertionError(f"unexpected glibc runner command: {command}")

        return runner

    def test_canonical_glibc_loader_paths_cover_supported_architectures(self) -> None:
        self.assertEqual(
            claude_linux._canonical_glibc_loader(self.host),
            pathlib.PurePosixPath("/lib64/ld-linux-x86-64.so.2"),
        )
        arm_host = dataclasses.replace(self.host, arch="arm64")
        self.assertEqual(
            claude_linux._canonical_glibc_loader(arm_host),
            pathlib.PurePosixPath("/lib/ld-linux-aarch64.so.1"),
        )

    def test_glibc_loader_version_window_is_floating_and_fail_closed(self) -> None:
        for rendered, expected in (
            (
                "ld.so (GNU libc) stable release version 2.27.\n",
                (2, 27),
            ),
            (
                "ld.so (Ubuntu GLIBC 2.39-0ubuntu8.7) stable release version 2.39.\n",
                (2, 39),
            ),
        ):
            with self.subTest(rendered=rendered):
                self.assertEqual(
                    claude_linux._parse_glibc_loader_version(rendered),
                    expected,
                )

        for rendered in (
            "ld.so (GNU libc) stable release version 2.26.\n",
            "ld.so (GNU libc) stable release version 3.0.\n",
            f"ld.so (GNU libc) stable release version {'9' * 10}.39.\n",
            "musl libc (x86_64) Version 1.2.5\n",
            "wrapper says GLIBC 2.39\n",
        ):
            with (
                self.subTest(rendered=rendered),
                self.assertRaises(claude_linux.LinuxHostDependencyUnavailable),
            ):
                claude_linux._parse_glibc_loader_version(rendered)

    def test_host_gpg_requires_canonical_glibc_interpreter(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            glibc = claude_linux.inspect_elf(_write_elf(root / "glibc-gpg"))
            self.assertEqual(
                claude_linux._require_safe_host_gpg_loader_policy(
                    glibc,
                    self.host,
                ),
                pathlib.PurePosixPath("/lib64/ld-linux-x86-64.so.2"),
            )
            musl = claude_linux.inspect_elf(
                _write_elf(
                    root / "musl-gpg",
                    interpreter="/lib/ld-musl-x86_64.so.1",
                )
            )
            with self.assertRaisesRegex(
                claude_linux.LinuxRuntimeUnsafe,
                "canonical glibc loader",
            ):
                claude_linux._require_safe_host_gpg_loader_policy(
                    musl,
                    self.host,
                )

    def test_glibc_loader_static_identity_rejects_unsafe_images(self) -> None:
        cases = (
            ({"arch": "arm64"}, "architecture"),
            (
                {"interpreter": "/lib64/ld-linux-x86-64.so.2"},
                "another interpreter",
            ),
            (
                {"dynamic_tags": (claude_linux.ELF_DYNAMIC_RUNPATH,)},
                "DT_RUNPATH",
            ),
            ({"elf_type": 2}, "ET_DYN"),
        )
        for index, (options, pattern) in enumerate(cases):
            with (
                self.subTest(options=options),
                tempfile.TemporaryDirectory(
                    dir=pathlib.Path(__file__).parent
                ) as temporary,
            ):
                root = pathlib.Path(temporary)
                root.chmod(0o700)
                settings = {"interpreter": None, **options}
                loader_path = _write_elf(
                    root / f"unsafe-loader-{index}",
                    **settings,
                )
                loader = claude_linux._capture_host_runtime_dependency(
                    loader_path,
                    claude_linux._CANONICAL_GLIBC_LOADERS["x64"],
                    trusted_owner_uids=self.trusted_owners,
                )
                with self.assertRaisesRegex(
                    claude_linux.LinuxRuntimeUnsafe,
                    pattern,
                ):
                    claude_linux._require_safe_glibc_loader(loader, self.host)

    def test_glibc_loader_must_be_executable(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            loader_path = _write_elf(
                root / "non-executable-loader",
                interpreter=None,
            )
            loader_path.chmod(0o400)
            loader = claude_linux._capture_host_runtime_dependency(
                loader_path,
                claude_linux._CANONICAL_GLIBC_LOADERS["x64"],
                trusted_owner_uids=self.trusted_owners,
            )
            with self.assertRaisesRegex(
                claude_linux.LinuxRuntimeUnsafe,
                "not executable",
            ):
                claude_linux._require_safe_glibc_loader(loader, self.host)

    def test_host_runtime_uses_verified_loader_version_and_list_commands(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            executable = _write_elf(root / "gpg")
            resolved_executable = str(executable.resolve(strict=True))
            loader = self._glibc_loader_fixture(root)
            calls: list[tuple[tuple[str, ...], dict[str, str]]] = []
            delegate = self._glibc_runner()

            def runner(argv, **kwargs):  # type: ignore[no-untyped-def]
                calls.append((tuple(argv), kwargs["env"]))
                return delegate(argv, **kwargs)

            with mock.patch.object(
                claude_linux,
                "_capture_glibc_loader",
                return_value=loader,
            ):
                closure = claude_linux.collect_host_runtime_closure(
                    self.host,
                    executable,
                    runner=runner,
                    trusted_owner_uids=self.trusted_owners,
                    executable_owner_uids=self.trusted_owners,
                )

        resolved_loader = str(loader.resolved_identity.path)
        self.assertEqual(
            tuple(command for command, _environment in calls),
            (
                (resolved_loader, "--version"),
                (resolved_loader, "--list", resolved_executable),
            ),
        )
        self.assertEqual(closure.glibc_version, (2, 39))
        self.assertEqual(closure.loader, loader)
        for _command, environment in calls:
            self.assertEqual(
                environment,
                claude_linux.fixed_host_tool_environment(),
            )

    def test_host_runtime_rejects_noncanonical_dependency_interpreter(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            executable = _write_elf(root / "gpg")
            library = _write_elf(
                root / "lib-with-interpreter.so",
                interpreter="/lib/ld-musl-x86_64.so.1",
            )
            loader = self._glibc_loader_fixture(root)
            runner = mock.Mock(side_effect=self._glibc_runner())
            with (
                mock.patch.object(
                    claude_linux,
                    "_capture_glibc_loader",
                    return_value=loader,
                ),
                mock.patch.object(
                    claude_linux,
                    "_parse_ldd_output",
                    return_value=(
                        claude_linux.RuntimeMount(
                            library,
                            pathlib.PurePosixPath("/lib/libunsafe.so"),
                        ),
                    ),
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxRuntimeUnsafe,
                    "noncanonical interpreter",
                ),
            ):
                claude_linux.collect_host_runtime_closure(
                    self.host,
                    executable,
                    runner=runner,
                    trusted_owner_uids=self.trusted_owners,
                    executable_owner_uids=self.trusted_owners,
                )
            self.assertEqual(runner.call_count, 2)

    def test_host_runtime_allows_canonical_dependency_interpreter(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            executable = _write_elf(root / "gpg")
            libc = _write_elf(root / "libc.so.6")
            loader = self._glibc_loader_fixture(root)
            with (
                mock.patch.object(
                    claude_linux,
                    "_capture_glibc_loader",
                    return_value=loader,
                ),
                mock.patch.object(
                    claude_linux,
                    "_parse_ldd_output",
                    return_value=(
                        claude_linux.RuntimeMount(
                            libc,
                            pathlib.PurePosixPath("/lib/libc.so.6"),
                        ),
                    ),
                ),
            ):
                closure = claude_linux.collect_host_runtime_closure(
                    self.host,
                    executable,
                    runner=self._glibc_runner(list_stdout=b"fixture\n"),
                    trusted_owner_uids=self.trusted_owners,
                    executable_owner_uids=self.trusted_owners,
                )

            self.assertTrue(
                any(
                    dependency.destination == pathlib.PurePosixPath("/lib/libc.so.6")
                    for dependency in closure.dependencies
                )
            )

    def test_accepts_and_revalidates_safe_system_path(self) -> None:
        candidate = next(
            path
            for path in (pathlib.Path("/usr/bin/env"), pathlib.Path("/bin/true"))
            if path.exists()
        )

        identity = claude_linux._capture_trusted_path_identity(candidate)

        self.assertEqual(
            claude_linux._revalidate_trusted_path_identity(identity),
            candidate.resolve(strict=True),
        )
        self.assertEqual(identity.components[-1].uid, 0)
        self.assertTrue(all(not (item.mode & 0o022) for item in identity.components))

    def test_rejects_writable_parent_as_unsafe(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            writable = root / "writable"
            writable.mkdir(mode=0o700)
            library = writable / "libunsafe.so"
            library.write_bytes(b"library")
            library.chmod(0o644)
            writable.chmod(0o777)

            with self.assertRaisesRegex(claude_linux.LinuxRuntimeUnsafe, "writable"):
                claude_linux._capture_trusted_path_identity(
                    library,
                    trusted_owner_uids=self.trusted_owners,
                )

    def test_rejects_replace_after_collect_as_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            ldd = root / "ldd"
            ldd.write_text("test-only\n", encoding="utf-8")
            ldd.chmod(0o500)
            library = root / "libstable.so"
            library.write_bytes(b"AAAA")
            library.chmod(0o444)
            executable = _write_elf(root / "program")

            with mock.patch.object(
                claude_linux,
                "_parse_ldd_output",
                return_value=(
                    claude_linux.RuntimeMount(
                        library,
                        pathlib.PurePosixPath("/lib/libstable.so"),
                    ),
                ),
            ):
                mounts = claude_linux.collect_runtime_libraries(
                    self.host,
                    (executable,),
                    runner=lambda *_args, **_kwargs: _capture(stdout=b"fixture\n"),
                    ldd_path=ldd,
                    ldd_trusted_roots=(root,),
                    trusted_owner_uids=self.trusted_owners,
                )
            replacement = root / "replacement.so"
            replacement.write_bytes(b"BBBB")
            replacement.chmod(0o444)
            os.replace(replacement, library)

            with self.assertRaisesRegex(
                claude_linux.LinuxRuntimeInspectionInconclusive,
                "changed after inspection",
            ):
                claude_linux.revalidate_runtime_libraries(self.host, mounts)

    def test_classifies_missing_ldd_and_probe_failure(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            executable = _write_elf(root / "program")
            with self.assertRaises(claude_linux.LinuxHostDependencyUnavailable):
                claude_linux.collect_runtime_libraries(
                    self.host,
                    (executable,),
                    ldd_path=root / "missing-ldd",
                    ldd_trusted_roots=(root,),
                    trusted_owner_uids=self.trusted_owners,
                )

            ldd = root / "ldd"
            ldd.write_text("test-only\n", encoding="utf-8")
            ldd.chmod(0o500)
            with self.assertRaises(claude_linux.LinuxRuntimeInspectionInconclusive):
                claude_linux.collect_runtime_libraries(
                    self.host,
                    (executable,),
                    runner=lambda *_args, **_kwargs: _capture(
                        returncode=1, stderr=b"temporary inspection failure"
                    ),
                    ldd_path=ldd,
                    ldd_trusted_roots=(root,),
                    trusted_owner_uids=self.trusted_owners,
                )

    def test_rejects_inconsistent_dynamic_mapping_before_ldd_execution(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            executable = _write_elf(
                root / "program",
                interpreter=None,
                dynamic_tags=(),
                dynamic_vaddr_delta=-1,
            )
            ldd = root / "ldd"
            ldd.write_text("test-only\n", encoding="utf-8")
            ldd.chmod(0o500)
            runner = mock.Mock(return_value=_capture(stdout=b"statically linked\n"))

            with self.assertRaisesRegex(
                claude_linux.LinuxRuntimeError,
                "PT_LOAD offset mapping is inconsistent",
            ):
                claude_linux.collect_runtime_libraries(
                    self.host,
                    (executable,),
                    runner=runner,
                    ldd_path=ldd,
                    ldd_trusted_roots=(root,),
                    trusted_owner_uids=self.trusted_owners,
                )

            runner.assert_not_called()

    def test_rejects_page_aliasing_load_before_ldd_execution(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            executable = _write_elf(
                root / "program",
                interpreter=None,
                dynamic_tags=(),
                extra_load_segments=(
                    (
                        0,
                        0,
                        claude_linux.ELF_HEADER_SIZE,
                        claude_linux.ELF_HEADER_SIZE,
                    ),
                ),
            )
            ldd = root / "ldd"
            ldd.write_text("test-only\n", encoding="utf-8")
            ldd.chmod(0o500)
            runner = mock.Mock(return_value=_capture(stdout=b"statically linked\n"))

            with self.assertRaisesRegex(
                claude_linux.LinuxRuntimeError,
                "page-rounded mapping overlaps",
            ):
                claude_linux.collect_runtime_libraries(
                    self.host,
                    (executable,),
                    runner=runner,
                    ldd_path=ldd,
                    ldd_trusted_roots=(root,),
                    trusted_owner_uids=self.trusted_owners,
                )

            runner.assert_not_called()

    def test_host_runtime_closure_rejects_rpath_and_runpath(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)

            for tag, label in (
                (claude_linux.ELF_DYNAMIC_RPATH, "DT_RPATH"),
                (claude_linux.ELF_DYNAMIC_RUNPATH, "DT_RUNPATH"),
            ):
                with self.subTest(tag=label):
                    executable = _write_elf(
                        root / f"gpg-{tag}",
                        dynamic_tags=(tag,),
                    )
                    runner = mock.Mock(return_value=_capture())
                    with self.assertRaisesRegex(
                        claude_linux.LinuxRuntimeUnsafe,
                        label,
                    ):
                        claude_linux.collect_host_runtime_closure(
                            self.host,
                            executable,
                            runner=runner,
                            trusted_owner_uids=self.trusted_owners,
                            executable_owner_uids=self.trusted_owners,
                        )
                    runner.assert_not_called()

    def test_elf_audit_tags_are_rejected_before_loader_execution(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            ldd = root / "ldd"
            ldd.write_text("test-only\n", encoding="utf-8")
            ldd.chmod(0o500)

            for tag, label in (
                (claude_linux.ELF_DYNAMIC_AUDIT, "DT_AUDIT"),
                (claude_linux.ELF_DYNAMIC_DEPAUDIT, "DT_DEPAUDIT"),
            ):
                for collector in ("host", "runtime"):
                    with self.subTest(tag=label, collector=collector):
                        executable = _write_elf(
                            root / f"gpg-{collector}-{tag}",
                            dynamic_tags=(tag,),
                        )
                        runner = mock.Mock(return_value=_capture())
                        with self.assertRaisesRegex(
                            claude_linux.LinuxRuntimeUnsafe,
                            label,
                        ):
                            if collector == "host":
                                claude_linux.collect_host_runtime_closure(
                                    self.host,
                                    executable,
                                    runner=runner,
                                    trusted_owner_uids=self.trusted_owners,
                                    executable_owner_uids=self.trusted_owners,
                                )
                            else:
                                claude_linux.collect_runtime_libraries(
                                    self.host,
                                    (executable,),
                                    runner=runner,
                                    ldd_path=ldd,
                                    ldd_trusted_roots=(root,),
                                    trusted_owner_uids=self.trusted_owners,
                                )
                        runner.assert_not_called()

    def test_host_runtime_closure_allows_private_snapshot_below_system_tmp(
        self,
    ) -> None:
        with (
            tempfile.TemporaryDirectory(dir=pathlib.Path(__file__).parent) as raw_tools,
            tempfile.TemporaryDirectory(dir="/tmp") as raw_private,
        ):
            tools = pathlib.Path(raw_tools)
            tools.chmod(0o700)
            private = pathlib.Path(raw_private)
            private.chmod(0o700)
            executable = _write_elf(private / "gpg")
            loader = self._glibc_loader_fixture(tools)

            with mock.patch.object(
                claude_linux,
                "_capture_glibc_loader",
                return_value=loader,
            ):
                closure = claude_linux.collect_host_runtime_closure(
                    self.host,
                    executable,
                    runner=self._glibc_runner(),
                    trusted_owner_uids=self.trusted_owners,
                    executable_owner_uids=self.trusted_owners,
                )

            self.assertTrue(closure.executable_identity.allow_root_sticky_temp_ancestor)
            self.assertTrue(
                closure.executable_identity.ignore_parent_directory_content_changes
            )
            self.assertTrue(
                any(
                    item.uid == 0 and stat.S_IMODE(item.mode) == 0o1777
                    for item in closure.executable_identity.components
                )
            )
            (private / "manifest.json").write_text("{}", encoding="utf-8")
            self.assertEqual(
                claude_linux.revalidate_host_runtime_closure(
                    closure,
                    runner=self._glibc_runner(),
                ),
                closure,
            )

    def test_host_runtime_closure_rejects_dependency_loader_policy_after_trace(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            executable = _write_elf(root / "gpg")
            for tag, label in (
                (claude_linux.ELF_DYNAMIC_RPATH, "DT_RPATH"),
                (claude_linux.ELF_DYNAMIC_RUNPATH, "DT_RUNPATH"),
                (claude_linux.ELF_DYNAMIC_AUDIT, "DT_AUDIT"),
                (claude_linux.ELF_DYNAMIC_DEPAUDIT, "DT_DEPAUDIT"),
            ):
                with self.subTest(tag=label):
                    library = _write_elf(
                        root / f"libunsafe-{tag}.so",
                        interpreter=None,
                        dynamic_tags=(tag,),
                    )
                    loader = self._glibc_loader_fixture(root)
                    runner = mock.Mock(side_effect=self._glibc_runner())

                    with (
                        mock.patch.object(
                            claude_linux,
                            "_capture_glibc_loader",
                            return_value=loader,
                        ),
                        mock.patch.object(
                            claude_linux,
                            "_parse_ldd_output",
                            return_value=(
                                claude_linux.RuntimeMount(
                                    library,
                                    pathlib.PurePosixPath("/lib/libunsafe.so"),
                                ),
                            ),
                        ),
                        self.assertRaisesRegex(
                            claude_linux.LinuxRuntimeUnsafe,
                            label,
                        ),
                    ):
                        claude_linux.collect_host_runtime_closure(
                            self.host,
                            executable,
                            runner=runner,
                            trusted_owner_uids=self.trusted_owners,
                            executable_owner_uids=self.trusted_owners,
                        )
                    self.assertEqual(runner.call_count, 2)

    def test_host_runtime_closure_detects_snapshot_replacement(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            executable = _write_elf(root / "gpg")
            loader = self._glibc_loader_fixture(root)
            with mock.patch.object(
                claude_linux,
                "_capture_glibc_loader",
                return_value=loader,
            ):
                closure = claude_linux.collect_host_runtime_closure(
                    self.host,
                    executable,
                    runner=self._glibc_runner(),
                    trusted_owner_uids=self.trusted_owners,
                    executable_owner_uids=self.trusted_owners,
                )
            replacement = _write_elf(root / "replacement")
            os.replace(replacement, executable)

            with self.assertRaisesRegex(
                claude_linux.LinuxRuntimeInspectionInconclusive,
                "changed after inspection",
            ):
                claude_linux.revalidate_host_runtime_closure(
                    closure,
                    runner=self._glibc_runner(),
                )

    def test_host_runtime_closure_detects_lexical_symlink_retarget(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            executable = _write_elf(root / "gpg")
            first = _write_elf(root / "lib-first.so", interpreter=None)
            second = _write_elf(root / "lib-second.so", interpreter=None)
            lexical = root / "libcurrent.so"
            lexical.symlink_to(first.name)
            loader = self._glibc_loader_fixture(root)
            parsed = (
                claude_linux.RuntimeMount(
                    lexical,
                    pathlib.PurePosixPath("/lib/libcurrent.so"),
                ),
            )

            with (
                mock.patch.object(
                    claude_linux,
                    "_capture_glibc_loader",
                    return_value=loader,
                ),
                mock.patch.object(
                    claude_linux,
                    "_parse_ldd_output",
                    return_value=parsed,
                ),
            ):
                closure = claude_linux.collect_host_runtime_closure(
                    self.host,
                    executable,
                    runner=self._glibc_runner(list_stdout=b"fixture\n"),
                    trusted_owner_uids=self.trusted_owners,
                    executable_owner_uids=self.trusted_owners,
                )
                lexical.unlink()
                lexical.symlink_to(second.name)
                with self.assertRaisesRegex(
                    claude_linux.LinuxRuntimeInspectionInconclusive,
                    "changed after inspection|resolved target changed",
                ):
                    claude_linux.revalidate_host_runtime_closure(
                        closure,
                        runner=self._glibc_runner(list_stdout=b"fixture\n"),
                    )

    def test_host_runtime_closure_is_recollected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            executable = _write_elf(root / "gpg")
            first = _write_elf(root / "lib-first.so", interpreter=None)
            second = _write_elf(root / "lib-second.so", interpreter=None)
            loader = self._glibc_loader_fixture(root)
            list_calls = 0

            def runner(argv, **_kwargs):  # type: ignore[no-untyped-def]
                nonlocal list_calls
                command = tuple(argv)
                if command[1] == "--version":
                    return self._glibc_runner()(command)
                self.assertEqual(command[1], "--list")
                list_calls += 1
                return _capture(stdout=f"closure-{list_calls}\n".encode())

            def parse(output, *, reject_unrecognized=False):  # type: ignore[no-untyped-def]
                self.assertTrue(reject_unrecognized)
                library = first if "closure-1" in output else second
                return (
                    claude_linux.RuntimeMount(
                        library,
                        pathlib.PurePosixPath("/lib/libselected.so"),
                    ),
                )

            with (
                mock.patch.object(
                    claude_linux,
                    "_capture_glibc_loader",
                    return_value=loader,
                ),
                mock.patch.object(
                    claude_linux,
                    "_parse_ldd_output",
                    side_effect=parse,
                ),
            ):
                closure = claude_linux.collect_host_runtime_closure(
                    self.host,
                    executable,
                    runner=runner,
                    trusted_owner_uids=self.trusted_owners,
                    executable_owner_uids=self.trusted_owners,
                )
                with self.assertRaisesRegex(
                    claude_linux.LinuxRuntimeInspectionInconclusive,
                    "closure changed",
                ):
                    claude_linux.revalidate_host_runtime_closure(
                        closure,
                        runner=runner,
                    )

            self.assertEqual(list_calls, 2)

    def test_host_runtime_loader_trace_timeout_is_inspection_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            executable = _write_elf(root / "gpg")
            loader = self._glibc_loader_fixture(root)

            def runner(argv, **_kwargs):  # type: ignore[no-untyped-def]
                command = tuple(argv)
                if command[1] == "--version":
                    return self._glibc_runner()(command)
                raise claude_linux.ReviewError("timeout fixture")

            with (
                mock.patch.object(
                    claude_linux,
                    "_capture_glibc_loader",
                    return_value=loader,
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxRuntimeInspectionInconclusive,
                    "host runtime dependency inspection failed",
                ),
            ):
                claude_linux.collect_host_runtime_closure(
                    self.host,
                    executable,
                    runner=runner,
                    trusted_owner_uids=self.trusted_owners,
                    executable_owner_uids=self.trusted_owners,
                )

        self.assertTrue(
            issubclass(
                claude_linux.LinuxHostDependencyUnavailable,
                claude_linux.LinuxIsolationUnavailable,
            )
        )
        self.assertFalse(
            issubclass(
                claude_linux.LinuxRuntimeInspectionInconclusive,
                claude_linux.LinuxIsolationUnavailable,
            )
        )


class CredentialStagingTest(unittest.TestCase):
    PROTOCOL = claude_refresh_lock.CLAUDE_REFRESH_LOCK_PROTOCOL_2_1_211

    # synthetic-token-fixtures IDs: access-expired, access-a, access-b,
    # refresh-a, refresh-b (pool joey-private-v1).
    SYNTH_ACCESS_EXPIRED = "codex_synth_v1_access_expired"
    SYNTH_ACCESS_A = "codex_synth_v1_access_a"
    SYNTH_ACCESS_B = "codex_synth_v1_access_b"
    SYNTH_REFRESH_A = "codex_synth_v1_refresh_a"
    SYNTH_REFRESH_B = "codex_synth_v1_refresh_b"

    def test_private_credential_update_forces_mode_under_restrictive_umask(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            parent_descriptor = os.open(
                root,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            payload = bytearray(b'{"credential":"synthetic"}\n')
            previous_umask = os.umask(0o777)
            try:
                candidate = claude_linux._create_private_credential_update(
                    parent_descriptor,
                    "credential.json",
                    payload,
                    owner_uid=os.geteuid(),
                )
            finally:
                os.umask(previous_umask)
                os.close(parent_descriptor)

            artifact = root / candidate
            self.assertEqual(artifact.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)

    def _credential(
        self,
        path: pathlib.Path,
        *,
        expires_at_ms: float,
        access_token: str = "not-a-real-token",
        refresh_token: str = "not-a-real-token",
    ) -> pathlib.Path:
        path.write_text(
            json.dumps(
                {
                    "claudeAiOauth": {
                        "accessToken": access_token,
                        "refreshToken": refresh_token,
                        "expiresAt": expires_at_ms,
                    }
                }
            ),
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path.resolve(strict=True)

    def _assert_retained_recovery_carrier(
        self,
        *,
        error: BaseException,
        staged: claude_linux.StagedCredential,
        helper: pathlib.Path,
        expected_refresh_token: str,
    ) -> None:
        self.assertEqual(
            getattr(error, "_codex_claude_retained_credential_carrier", None),
            str(staged.carrier_root),
        )
        self.assertTrue(
            getattr(error, "_codex_claude_refresh_persistence_failed", False)
        )
        remaining = list(helper.iterdir())
        self.assertEqual(len(remaining), 1)
        self.assertTrue(remaining[0].samefile(staged.carrier_root))
        self.assertEqual(
            stat.S_IMODE(staged.carrier_root.stat().st_mode),
            0o700,
        )
        self.assertEqual(
            stat.S_IMODE(staged.config_dir.stat().st_mode),
            0o700,
        )
        self.assertEqual(
            stat.S_IMODE(staged.credential_path.stat().st_mode),
            0o600,
        )
        retained = json.loads(staged.credential_path.read_text(encoding="utf-8"))
        self.assertEqual(
            retained["claudeAiOauth"]["refreshToken"],
            expected_refresh_token,
        )

    def test_stages_private_fresh_copy_and_cleans_it(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json", expires_at_ms=(now + 7200) * 1000
            )
            source_payload = source.read_bytes()

            with claude_linux.stage_claude_credentials(
                source, helper, now=now, required_validity_seconds=3600
            ) as staged:
                staged_dir = staged.config_dir
                self.assertEqual(staged.credential_path.read_bytes(), source_payload)
                self.assertEqual(
                    stat.S_IMODE(staged.credential_path.stat().st_mode), 0o600
                )
                self.assertEqual(stat.S_IMODE(staged.config_dir.stat().st_mode), 0o700)

            self.assertFalse(staged_dir.exists())
            self.assertEqual(source.read_bytes(), source_payload)

    def test_rejects_credential_symlink_ancestor(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            real_home = root / "real-home"
            config_dir = real_home / ".claude"
            config_dir.mkdir(parents=True, mode=0o700)
            self._credential(
                config_dir / ".credentials.json",
                expires_at_ms=(now + 7200) * 1000,
            )
            linked_home = root / "linked-home"
            linked_home.symlink_to(real_home, target_is_directory=True)
            linked_config = real_home / "linked-config"
            linked_config.symlink_to(config_dir, target_is_directory=True)
            helper = root / "helper"
            helper.mkdir(mode=0o700)

            for label, candidate in (
                (
                    "early ancestor",
                    linked_home / ".claude" / ".credentials.json",
                ),
                (
                    "direct parent",
                    linked_config / ".credentials.json",
                ),
            ):
                with self.subTest(label=label):
                    with self.assertRaisesRegex(
                        claude_linux.LinuxCredentialUnsafe,
                        "symlink",
                    ):
                        with claude_linux.stage_claude_credentials(
                            candidate,
                            helper,
                            now=now,
                        ):
                            pass

    def test_credential_ancestor_retarget_cannot_redirect_initial_read(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            home = root / "home"
            config_dir = home / ".claude"
            config_dir.mkdir(parents=True, mode=0o700)
            source = self._credential(
                config_dir / ".credentials.json",
                expires_at_ms=(now + 7200) * 1000,
                access_token=self.SYNTH_ACCESS_A,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            original_payload = source.read_bytes()

            replacement_home = root / "replacement-home"
            replacement_config = replacement_home / ".claude"
            replacement_config.mkdir(parents=True, mode=0o700)
            replacement_source = self._credential(
                replacement_config / ".credentials.json",
                expires_at_ms=(now + 7200) * 1000,
                access_token=self.SYNTH_ACCESS_B,
                refresh_token=self.SYNTH_REFRESH_B,
            )
            replacement_payload = replacement_source.read_bytes()
            retained_home = root / "retained-home"
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            real_validate = claude_linux._validate_private_directory
            retargeted = False

            def validate_then_retarget(
                path: pathlib.Path,
                *,
                owner_uid: int,
            ) -> pathlib.Path:
                nonlocal retargeted
                validated = real_validate(path, owner_uid=owner_uid)
                if not retargeted:
                    home.rename(retained_home)
                    home.symlink_to(replacement_home, target_is_directory=True)
                    retargeted = True
                return validated

            with (
                mock.patch.object(
                    claude_linux,
                    "_validate_private_directory",
                    side_effect=validate_then_retarget,
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialInspectionInconclusive,
                    "ancestor changed",
                ),
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                ) as staged:
                    self.assertEqual(
                        staged.credential_path.read_bytes(),
                        original_payload,
                    )

            self.assertTrue(retargeted)
            self.assertEqual(
                (retained_home / ".claude" / ".credentials.json").read_bytes(),
                original_payload,
            )
            self.assertEqual(
                (home / ".claude" / ".credentials.json").read_bytes(),
                replacement_payload,
            )
            self.assertEqual(list(helper.iterdir()), [])

    def test_credential_ancestor_retarget_cannot_redirect_writeback(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            home = root / "home"
            config_dir = home / ".claude"
            config_dir.mkdir(parents=True, mode=0o700)
            source = self._credential(
                config_dir / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            original_payload = source.read_bytes()

            replacement_home = root / "replacement-home"
            replacement_config = replacement_home / ".claude"
            replacement_config.mkdir(parents=True, mode=0o700)
            replacement_source = self._credential(
                replacement_config / ".credentials.json",
                expires_at_ms=(now + 7200) * 1000,
                access_token=self.SYNTH_ACCESS_B,
                refresh_token=self.SYNTH_REFRESH_B,
            )
            replacement_payload = replacement_source.read_bytes()
            retained_home = root / "retained-home"
            helper = root / "helper"
            helper.mkdir(mode=0o700)

            with (
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_POLL_SECONDS",
                    60.0,
                ),
                self.assertRaises(
                    claude_linux.LinuxCredentialInspectionInconclusive
                ) as raised,
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ) as staged:
                    self._credential(
                        staged.credential_path,
                        expires_at_ms=(now + 7200) * 1000,
                        access_token=self.SYNTH_ACCESS_A,
                        refresh_token=self.SYNTH_REFRESH_B,
                    )
                    home.rename(retained_home)
                    home.symlink_to(replacement_home, target_is_directory=True)

            self.assertEqual(
                (retained_home / ".claude" / ".credentials.json").read_bytes(),
                original_payload,
            )
            self.assertEqual(
                (home / ".claude" / ".credentials.json").read_bytes(),
                replacement_payload,
            )
            self._assert_retained_recovery_carrier(
                error=raised.exception,
                staged=staged,
                helper=helper,
                expected_refresh_token=self.SYNTH_REFRESH_B,
            )

    def test_blocked_anchor_check_cannot_block_timeout_handoff(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            config_dir = root / ".claude"
            config_dir.mkdir(mode=0o700)
            source = self._credential(
                config_dir / ".credentials.json",
                expires_at_ms=(now + 7200) * 1000,
            )
            anchor = claude_linux._open_credential_directory_anchor(
                source,
                owner_uid=os.getuid(),
            )
            target_fd = anchor._descriptors[0]
            real_fstat = claude_linux.os.fstat
            inspection_entered = threading.Event()
            release_inspection = threading.Event()
            inspection_errors: list[BaseException] = []

            def blocking_fstat(descriptor: int) -> os.stat_result:
                if descriptor == target_fd and not inspection_entered.is_set():
                    inspection_entered.set()
                    if not release_inspection.wait(timeout=2.0):
                        raise TimeoutError("anchor inspection fixture timed out")
                return real_fstat(descriptor)

            def inspect_anchor() -> None:
                try:
                    anchor.assert_stable(owner_uid=os.getuid())
                except BaseException as error:
                    inspection_errors.append(error)

            inspection_worker = threading.Thread(target=inspect_anchor)
            detach_worker = threading.Thread(target=anchor.detach_to_watcher)
            detached_before_release = False
            try:
                with mock.patch.object(
                    claude_linux.os,
                    "fstat",
                    side_effect=blocking_fstat,
                ):
                    inspection_worker.start()
                    self.assertTrue(inspection_entered.wait(timeout=1.0))
                    detach_worker.start()
                    detach_worker.join(timeout=0.2)
                    detached_before_release = not detach_worker.is_alive()
                    release_inspection.set()
                    inspection_worker.join(timeout=1.0)
                    detach_worker.join(timeout=1.0)
                self.assertFalse(inspection_worker.is_alive())
                self.assertFalse(detach_worker.is_alive())
                self.assertTrue(detached_before_release)
                self.assertEqual(inspection_errors, [])
            finally:
                release_inspection.set()
                inspection_worker.join(timeout=1.0)
                if detach_worker.ident is not None:
                    detach_worker.join(timeout=1.0)
                if anchor.detached_to_watcher:
                    anchor.close_if_detached()
                else:
                    anchor.close_if_owned()

    def test_source_anchor_timeout_handoff_closes_in_both_interleavings(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            for cleanup_first in (True, False):
                with self.subTest(cleanup_first=cleanup_first):
                    config_dir = root / f"config-{cleanup_first}"
                    config_dir.mkdir(mode=0o700)
                    source = self._credential(
                        config_dir / ".credentials.json",
                        expires_at_ms=(now + 7200) * 1000,
                    )
                    anchor = claude_linux._open_credential_directory_anchor(
                        source,
                        owner_uid=os.getuid(),
                    )
                    staged = claude_linux.StagedCredential(
                        config_dir,
                        config_dir,
                        source,
                        (now + 7200) * 1000,
                    )
                    watcher = claude_linux._StagedCredentialWatcher(
                        source=source,
                        source_anchor=anchor,
                        staged=staged,
                        original_payload=bytearray(b"{}"),
                        original_identity=mock.Mock(),
                        parent_identity=anchor.identity,
                        owner_uid=os.getuid(),
                        refresh_lock_protocol=self.PROTOCOL,
                    )
                    try:
                        if cleanup_first:
                            watcher._close_source_anchor_after_worker()
                            watcher.retain_source_anchor_after_timeout()
                        else:
                            watcher.retain_source_anchor_after_timeout()
                            self.assertIsInstance(anchor.descriptor, int)
                            watcher._close_source_anchor_after_worker()
                        with self.assertRaisesRegex(
                            claude_linux.LinuxCredentialInspectionInconclusive,
                            "anchor is closed",
                        ):
                            _ = anchor.descriptor
                    finally:
                        watcher.scrub()
                        if anchor.detached_to_watcher:
                            anchor.close_if_detached()
                        else:
                            anchor.close_if_owned()

    def test_default_accepts_one_second_remaining(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now + 1) * 1000,
            )

            with claude_linux.stage_claude_credentials(
                source,
                helper,
                now=now,
            ) as staged:
                self.assertEqual(staged.expires_at_ms, (now + 1) * 1000)

    def test_explicit_zero_accepts_unexpired_credential(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now + 1) * 1000,
            )

            with claude_linux.stage_claude_credentials(
                source,
                helper,
                now=now,
                required_validity_seconds=0,
            ):
                pass

    def test_default_accepts_expired_credential_for_runtime_refresh(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=now * 1000,
            )

            with claude_linux.stage_claude_credentials(
                source,
                helper,
                now=now,
            ) as staged:
                self.assertEqual(staged.expires_at_ms, now * 1000)

    def test_rejects_negative_required_validity(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now + 1) * 1000,
            )

            with self.assertRaisesRegex(
                claude_linux.LinuxCredentialUnsafe,
                "non-negative",
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    required_validity_seconds=-1,
                ):
                    pass

    def test_writes_back_valid_runtime_refresh_atomically(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            original_inode = source.stat().st_ino

            with claude_linux.stage_claude_credentials(
                source,
                helper,
                now=now,
                refresh_lock_protocol=self.PROTOCOL,
            ) as staged:
                refreshed = self._credential(
                    staged.config_dir / "refreshed-credentials.json",
                    expires_at_ms=(now + 7200) * 1000,
                    access_token=self.SYNTH_ACCESS_A,
                    refresh_token=self.SYNTH_REFRESH_B,
                )
                refreshed.replace(staged.credential_path)

            value = json.loads(source.read_text(encoding="utf-8"))
            oauth = value["claudeAiOauth"]
            self.assertEqual(oauth["accessToken"], self.SYNTH_ACCESS_A)
            self.assertEqual(oauth["refreshToken"], self.SYNTH_REFRESH_B)
            self.assertNotEqual(source.stat().st_ino, original_inode)
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o600)
            self.assertEqual(list(helper.iterdir()), [])

    def test_watcher_persists_multiple_rotations_before_context_exit(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            persisted_b = threading.Event()
            persisted_a = threading.Event()
            real_writeback = claude_linux._writeback_refreshed_credential_impl

            def observe_writeback(*args: object, **kwargs: object) -> object:
                result = real_writeback(*args, **kwargs)
                candidate = kwargs.get("staged_payload")
                if isinstance(candidate, bytearray):
                    value = json.loads(candidate)
                    refresh = value["claudeAiOauth"]["refreshToken"]
                    if refresh == self.SYNTH_REFRESH_B:
                        persisted_b.set()
                    elif refresh == self.SYNTH_REFRESH_A:
                        persisted_a.set()
                return result

            with mock.patch.object(
                claude_linux,
                "_writeback_refreshed_credential_impl",
                side_effect=observe_writeback,
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ) as staged:
                    first = self._credential(
                        staged.config_dir / "rotation-b.json",
                        expires_at_ms=(now + 3600) * 1000,
                        access_token=self.SYNTH_ACCESS_A,
                        refresh_token=self.SYNTH_REFRESH_B,
                    )
                    first.replace(staged.credential_path)
                    self.assertTrue(persisted_b.wait(timeout=3.0))
                    value = json.loads(source.read_text(encoding="utf-8"))
                    self.assertEqual(
                        value["claudeAiOauth"]["refreshToken"],
                        self.SYNTH_REFRESH_B,
                    )

                    second = self._credential(
                        staged.config_dir / "rotation-a.json",
                        expires_at_ms=(now + 7200) * 1000,
                        access_token=self.SYNTH_ACCESS_B,
                        refresh_token=self.SYNTH_REFRESH_A,
                    )
                    second.replace(staged.credential_path)
                    self.assertTrue(persisted_a.wait(timeout=3.0))
                    value = json.loads(source.read_text(encoding="utf-8"))
                    self.assertEqual(
                        value["claudeAiOauth"]["refreshToken"],
                        self.SYNTH_REFRESH_A,
                    )

            value = json.loads(source.read_text(encoding="utf-8"))
            self.assertEqual(
                value["claudeAiOauth"]["accessToken"],
                self.SYNTH_ACCESS_B,
            )
            self.assertEqual(list(helper.iterdir()), [])

    def test_final_drain_persists_last_rotation_before_cleanup(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )

            with mock.patch.object(
                claude_linux,
                "STAGED_CREDENTIAL_POLL_SECONDS",
                60.0,
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ) as staged:
                    refreshed = self._credential(
                        staged.config_dir / "last-rotation.json",
                        expires_at_ms=(now + 7200) * 1000,
                        access_token=self.SYNTH_ACCESS_A,
                        refresh_token=self.SYNTH_REFRESH_B,
                    )
                    refreshed.replace(staged.credential_path)

            value = json.loads(source.read_text(encoding="utf-8"))
            self.assertEqual(
                value["claudeAiOauth"]["refreshToken"],
                self.SYNTH_REFRESH_B,
            )
            self.assertEqual(list(helper.iterdir()), [])

    def test_final_drain_recovers_abandoned_helper_owned_refresh_locks(
        self,
    ) -> None:
        now = time.time()
        for include_legacy in (False, True):
            for stale in (False, True):
                self._run_staged_refresh_lock_recovery_case(
                    now=now,
                    include_legacy=include_legacy,
                    stale=stale,
                )

    def _run_staged_refresh_lock_recovery_case(
        self,
        *,
        now: float,
        include_legacy: bool,
        stale: bool,
    ) -> None:
        with (
            self.subTest(include_legacy=include_legacy, stale=stale),
            tempfile.TemporaryDirectory() as temporary,
        ):
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )

            with (
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_POLL_SECONDS",
                    60.0,
                ),
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_RETRY_SECONDS",
                    0.0,
                ),
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_LOCK_TIMEOUT_SECONDS",
                    0.0,
                ),
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                    writer_quiescent=lambda: True,
                ) as staged:
                    refreshed = self._credential(
                        staged.config_dir / "last-rotation.json",
                        expires_at_ms=(now + 7200) * 1000,
                        access_token=self.SYNTH_ACCESS_A,
                        refresh_token=self.SYNTH_REFRESH_B,
                    )
                    refreshed.replace(staged.credential_path)
                    primary = staged.config_dir / ".oauth_refresh.lock"
                    primary.mkdir(mode=0o700)
                    locks = [primary]
                    if include_legacy:
                        legacy = pathlib.Path(str(staged.config_dir) + ".lock")
                        legacy.mkdir(mode=0o700)
                        locks.append(legacy)
                    if stale:
                        stale_time = now - self.PROTOCOL.stale_seconds - 5.0
                        for lock in locks:
                            os.utime(lock, (stale_time, stale_time))

            value = json.loads(source.read_text(encoding="utf-8"))
            self.assertEqual(
                value["claudeAiOauth"]["refreshToken"],
                self.SYNTH_REFRESH_B,
            )
            self.assertEqual(list(helper.iterdir()), [])

    def test_unproven_writer_retains_rotated_private_recovery_carrier(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            staged: claude_linux.StagedCredential | None = None

            with (
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_POLL_SECONDS",
                    60.0,
                ),
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_RETRY_SECONDS",
                    0.0,
                ),
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_LOCK_TIMEOUT_SECONDS",
                    0.0,
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialInspectionInconclusive,
                    "private recovery carrier was retained",
                ) as raised,
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                    writer_quiescent=lambda: False,
                ) as staged:
                    refreshed = self._credential(
                        staged.config_dir / "last-rotation.json",
                        expires_at_ms=(now + 7200) * 1000,
                        access_token=self.SYNTH_ACCESS_A,
                        refresh_token=self.SYNTH_REFRESH_B,
                    )
                    refreshed.replace(staged.credential_path)
                    (staged.config_dir / ".oauth_refresh.lock").mkdir(mode=0o700)

            assert staged is not None
            self.assertIn(str(staged.carrier_root), str(raised.exception))
            self._assert_retained_recovery_carrier(
                error=raised.exception,
                staged=staged,
                helper=helper,
                expected_refresh_token=self.SYNTH_REFRESH_B,
            )
            host = json.loads(source.read_text(encoding="utf-8"))
            self.assertEqual(
                host["claudeAiOauth"]["refreshToken"],
                self.SYNTH_REFRESH_A,
            )

    def test_stale_host_refresh_lock_is_never_reclaimed(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            host_lock = root / ".oauth_refresh.lock"
            host_lock.mkdir(mode=0o700)
            stale_time = now - self.PROTOCOL.stale_seconds - 5.0
            os.utime(host_lock, (stale_time, stale_time))

            with (
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_POLL_SECONDS",
                    60.0,
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialInspectionInconclusive,
                    "stale Claude refresh lock",
                ) as raised,
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                    writer_quiescent=lambda: True,
                ) as staged:
                    refreshed = self._credential(
                        staged.config_dir / "last-rotation.json",
                        expires_at_ms=(now + 7200) * 1000,
                        access_token=self.SYNTH_ACCESS_A,
                        refresh_token=self.SYNTH_REFRESH_B,
                    )
                    refreshed.replace(staged.credential_path)

            self.assertTrue(host_lock.is_dir())
            self._assert_retained_recovery_carrier(
                error=raised.exception,
                staged=staged,
                helper=helper,
                expected_refresh_token=self.SYNTH_REFRESH_B,
            )
            host = json.loads(source.read_text(encoding="utf-8"))
            self.assertEqual(
                host["claudeAiOauth"]["refreshToken"],
                self.SYNTH_REFRESH_A,
            )

    def test_unchanged_poll_does_not_take_any_refresh_lock(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            poll_observed = threading.Event()
            observation_count = 0
            real_observation = claude_linux._staged_credential_observation

            def observe_poll(
                path: pathlib.Path,
            ) -> claude_linux._CredentialFileIdentity:
                nonlocal observation_count
                result = real_observation(path)
                observation_count += 1
                if observation_count >= 2:
                    poll_observed.set()
                return result

            with (
                mock.patch.object(
                    claude_linux,
                    "_staged_credential_observation",
                    side_effect=observe_poll,
                ),
                mock.patch.object(
                    claude_linux,
                    "acquire_claude_refresh_lock",
                    wraps=claude_linux.acquire_claude_refresh_lock,
                ) as acquire_lock,
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ):
                    self.assertTrue(poll_observed.wait(timeout=3.0))
                    acquire_lock.assert_not_called()

            self.assertEqual(list(helper.iterdir()), [])

    def test_changed_credential_without_certified_protocol_is_inconclusive(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            original = source.read_bytes()

            with self.assertRaisesRegex(
                claude_linux.LinuxCredentialInspectionInconclusive,
                "protocol is unavailable",
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                ) as staged:
                    self._credential(
                        staged.credential_path,
                        expires_at_ms=(now + 7200) * 1000,
                        access_token=self.SYNTH_ACCESS_A,
                        refresh_token=self.SYNTH_REFRESH_B,
                    )

            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(list(helper.iterdir()), [])

    def test_unchanged_staged_credential_skips_writeback(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            original_payload = source.read_bytes()
            original_inode = source.stat().st_ino

            with mock.patch.object(
                claude_linux.os,
                "replace",
                wraps=os.replace,
            ) as replace_mock:
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                ):
                    pass

            replace_mock.assert_not_called()
            self.assertEqual(source.read_bytes(), original_payload)
            self.assertEqual(source.stat().st_ino, original_inode)
            self.assertEqual(list(helper.iterdir()), [])

    def test_concurrent_source_change_makes_refresh_writeback_inconclusive(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            real_create_update = claude_linux._create_private_credential_update

            def create_then_change_source(
                *args: object,
                **kwargs: object,
            ) -> str:
                candidate = real_create_update(*args, **kwargs)
                self._credential(
                    source,
                    expires_at_ms=(now + 3600) * 1000,
                    access_token=self.SYNTH_ACCESS_B,
                    refresh_token=self.SYNTH_REFRESH_A,
                )
                return candidate

            with (
                mock.patch.object(
                    claude_linux,
                    "_create_private_credential_update",
                    side_effect=create_then_change_source,
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialInspectionInconclusive,
                    "changed concurrently",
                ) as raised,
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ) as staged:
                    self._credential(
                        staged.credential_path,
                        expires_at_ms=(now + 7200) * 1000,
                        access_token=self.SYNTH_ACCESS_A,
                        refresh_token=self.SYNTH_REFRESH_B,
                    )

            value = json.loads(source.read_text(encoding="utf-8"))
            oauth = value["claudeAiOauth"]
            self.assertEqual(oauth["accessToken"], self.SYNTH_ACCESS_B)
            self.assertEqual(oauth["refreshToken"], self.SYNTH_REFRESH_A)
            self.assertEqual(
                list(root.glob("..credentials.json.codex-review-*")),
                [],
            )
            self._assert_retained_recovery_carrier(
                error=raised.exception,
                staged=staged,
                helper=helper,
                expected_refresh_token=self.SYNTH_REFRESH_B,
            )

    def test_watcher_never_adopts_an_external_host_credential_change(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )

            with self.assertRaisesRegex(
                claude_linux.LinuxCredentialInspectionInconclusive,
                "changed concurrently",
            ) as raised:
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ) as staged:
                    self._credential(
                        source,
                        expires_at_ms=(now + 3600) * 1000,
                        access_token=self.SYNTH_ACCESS_B,
                        refresh_token=self.SYNTH_REFRESH_A,
                    )
                    refreshed = self._credential(
                        staged.config_dir / "rotation-b.json",
                        expires_at_ms=(now + 7200) * 1000,
                        access_token=self.SYNTH_ACCESS_A,
                        refresh_token=self.SYNTH_REFRESH_B,
                    )
                    refreshed.replace(staged.credential_path)

            value = json.loads(source.read_text(encoding="utf-8"))
            self.assertEqual(
                value["claudeAiOauth"]["accessToken"],
                self.SYNTH_ACCESS_B,
            )
            self.assertEqual(
                value["claudeAiOauth"]["refreshToken"],
                self.SYNTH_REFRESH_A,
            )
            self._assert_retained_recovery_carrier(
                error=raised.exception,
                staged=staged,
                helper=helper,
                expected_refresh_token=self.SYNTH_REFRESH_B,
            )

    def test_watcher_join_completes_before_carrier_cleanup(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            joined = threading.Event()
            cleaned = threading.Event()
            real_wait = claude_linux._StagedCredentialWatcher.wait_until_stopped
            real_cleanup = claude_linux._cleanup_staged_credential

            def wait_then_mark(
                watcher: claude_linux._StagedCredentialWatcher,
            ) -> bool:
                result = real_wait(watcher)
                joined.set()
                return result

            def assert_joined_then_cleanup(
                staged: claude_linux.StagedCredential,
            ) -> BaseException | None:
                self.assertTrue(joined.is_set())
                self.assertFalse(
                    any(
                        thread.name == "codex-claude-staged-credential-watcher"
                        and thread.is_alive()
                        for thread in threading.enumerate()
                    )
                )
                cleaned.set()
                return real_cleanup(staged)

            with (
                mock.patch.object(
                    claude_linux._StagedCredentialWatcher,
                    "wait_until_stopped",
                    autospec=True,
                    side_effect=wait_then_mark,
                ),
                mock.patch.object(
                    claude_linux,
                    "_cleanup_staged_credential",
                    side_effect=assert_joined_then_cleanup,
                ),
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ):
                    pass

            self.assertTrue(cleaned.is_set())
            self.assertEqual(list(helper.iterdir()), [])

    def test_watcher_join_timeout_retains_rotated_private_recovery_carrier(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            drain_started = threading.Event()
            release_drain = threading.Event()
            real_start = claude_linux._StagedCredentialWatcher.start
            watchers: list[claude_linux._StagedCredentialWatcher] = []

            def start_and_capture(
                watcher: claude_linux._StagedCredentialWatcher,
            ) -> None:
                watchers.append(watcher)
                real_start(watcher)

            def block_worker_drain(
                _watcher: claude_linux._StagedCredentialWatcher,
                *,
                final: bool,
            ) -> None:
                self.assertFalse(final)
                drain_started.set()
                self.assertTrue(release_drain.wait(timeout=5.0))

            with (
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_POLL_SECONDS",
                    0.01,
                ),
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_JOIN_TIMEOUT_SECONDS",
                    0.01,
                ),
                mock.patch.object(
                    claude_linux._StagedCredentialWatcher,
                    "_drain",
                    autospec=True,
                    side_effect=block_worker_drain,
                ),
                mock.patch.object(
                    claude_linux._StagedCredentialWatcher,
                    "start",
                    autospec=True,
                    side_effect=start_and_capture,
                ),
            ):
                manager = claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                )
                staged = manager.__enter__()
                rotated = self._credential(
                    staged.config_dir / "join-timeout-rotation.json",
                    expires_at_ms=(now + 7200) * 1000,
                    access_token=self.SYNTH_ACCESS_A,
                    refresh_token=self.SYNTH_REFRESH_B,
                )
                rotated.replace(staged.credential_path)
                self.assertTrue(drain_started.wait(timeout=3.0))
                exit_errors: list[BaseException] = []
                exit_done = threading.Event()

                def finish_context() -> None:
                    try:
                        manager.__exit__(None, None, None)
                    except BaseException as error:
                        exit_errors.append(error)
                    finally:
                        exit_done.set()

                owner = threading.Thread(target=finish_context, daemon=True)
                owner.start()
                try:
                    self.assertTrue(exit_done.wait(timeout=0.5))
                    self.assertEqual(len(exit_errors), 1)
                    self.assertIsInstance(
                        exit_errors[0],
                        claude_linux.LinuxCredentialInspectionInconclusive,
                    )
                    self._assert_retained_recovery_carrier(
                        error=exit_errors[0],
                        staged=staged,
                        helper=helper,
                        expected_refresh_token=self.SYNTH_REFRESH_B,
                    )
                    host = json.loads(source.read_text(encoding="utf-8"))
                    self.assertEqual(
                        host["claudeAiOauth"]["refreshToken"],
                        self.SYNTH_REFRESH_A,
                    )
                finally:
                    release_drain.set()
                    owner.join(timeout=3.0)
                    if watchers:
                        deadline = time.monotonic() + 3.0
                        while watchers[0].is_alive() and time.monotonic() < deadline:
                            time.sleep(0.01)
                        self.assertFalse(watchers[0].is_alive())

                self.assertFalse(owner.is_alive())
                self.assertEqual(len(watchers), 1)
                self.assertTrue(watchers[0]._thread.daemon)

            self._assert_retained_recovery_carrier(
                error=exit_errors[0],
                staged=staged,
                helper=helper,
                expected_refresh_token=self.SYNTH_REFRESH_B,
            )

    def test_timeout_handoff_close_failure_retains_recovery_carrier(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            watchers: list[claude_linux._StagedCredentialWatcher] = []

            def capture_without_starting(
                watcher: claude_linux._StagedCredentialWatcher,
            ) -> None:
                watchers.append(watcher)

            def detach_then_fail_close(
                watcher: claude_linux._StagedCredentialWatcher,
            ) -> None:
                watcher._source_anchor.detach_to_watcher()
                with watcher._source_anchor_handoff_lock:
                    watcher._source_anchor_cleanup_reached = True
                raise claude_linux.LinuxCredentialInspectionInconclusive(
                    "injected descriptor-chain close failure"
                )

            with (
                mock.patch.object(
                    claude_linux._StagedCredentialWatcher,
                    "start",
                    autospec=True,
                    side_effect=capture_without_starting,
                ),
                mock.patch.object(
                    claude_linux._StagedCredentialWatcher,
                    "request_stop",
                    autospec=True,
                    return_value=None,
                ),
                mock.patch.object(
                    claude_linux._StagedCredentialWatcher,
                    "wait_until_stopped",
                    autospec=True,
                    return_value=False,
                ),
                mock.patch.object(
                    claude_linux._StagedCredentialWatcher,
                    "retain_source_anchor_after_timeout",
                    autospec=True,
                    side_effect=detach_then_fail_close,
                ),
                mock.patch.object(
                    claude_linux._StagedCredentialWatcher,
                    "is_alive",
                    autospec=True,
                    return_value=False,
                ),
                self.assertRaises(
                    claude_linux.LinuxCredentialInspectionInconclusive
                ) as raised,
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ) as staged:
                    self._credential(
                        staged.credential_path,
                        expires_at_ms=(now + 7200) * 1000,
                        access_token=self.SYNTH_ACCESS_A,
                        refresh_token=self.SYNTH_REFRESH_B,
                    )

            self.assertEqual(len(watchers), 1)
            self._assert_retained_recovery_carrier(
                error=raised.exception,
                staged=staged,
                helper=helper,
                expected_refresh_token=self.SYNTH_REFRESH_B,
            )
            watchers[0]._source_anchor.close_if_detached()

    def test_stop_closes_background_writeback_after_candidate_read(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            candidate_read = threading.Event()
            release_candidate = threading.Event()
            background_writeback_called = threading.Event()
            real_read = claude_linux._read_staged_credential_under_lock
            real_writeback = claude_linux._writeback_refreshed_credential
            real_start = claude_linux._StagedCredentialWatcher.start
            watchers: list[claude_linux._StagedCredentialWatcher] = []

            def read_then_block(*args: object, **kwargs: object):
                stable = real_read(*args, **kwargs)
                if (
                    stable is not None
                    and threading.current_thread().name
                    == "codex-claude-staged-credential-watcher"
                ):
                    candidate, _identity = stable
                    value = json.loads(candidate)
                    if value["claudeAiOauth"]["refreshToken"] == self.SYNTH_REFRESH_B:
                        candidate_read.set()
                        self.assertTrue(release_candidate.wait(timeout=5.0))
                return stable

            def observe_writeback(*args: object, **kwargs: object):
                if (
                    threading.current_thread().name
                    == "codex-claude-staged-credential-watcher"
                ):
                    background_writeback_called.set()
                return real_writeback(*args, **kwargs)

            def start_and_capture(
                watcher: claude_linux._StagedCredentialWatcher,
            ) -> None:
                watchers.append(watcher)
                real_start(watcher)

            with (
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_POLL_SECONDS",
                    0.01,
                ),
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_JOIN_TIMEOUT_SECONDS",
                    0.01,
                ),
                mock.patch.object(
                    claude_linux,
                    "_read_staged_credential_under_lock",
                    side_effect=read_then_block,
                ),
                mock.patch.object(
                    claude_linux,
                    "_writeback_refreshed_credential",
                    side_effect=observe_writeback,
                ),
                mock.patch.object(
                    claude_linux._StagedCredentialWatcher,
                    "start",
                    autospec=True,
                    side_effect=start_and_capture,
                ),
            ):
                manager = claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                )
                staged = manager.__enter__()
                rotated = self._credential(
                    staged.config_dir / "post-read-stop-rotation.json",
                    expires_at_ms=(now + 7200) * 1000,
                    access_token=self.SYNTH_ACCESS_A,
                    refresh_token=self.SYNTH_REFRESH_B,
                )
                rotated.replace(staged.credential_path)
                self.assertTrue(candidate_read.wait(timeout=3.0))

                exit_errors: list[BaseException] = []

                def finish_context() -> None:
                    try:
                        manager.__exit__(None, None, None)
                    except BaseException as error:
                        exit_errors.append(error)

                owner = threading.Thread(target=finish_context, daemon=True)
                owner.start()
                owner.join(timeout=1.0)
                self.assertFalse(owner.is_alive())
                self.assertEqual(len(exit_errors), 1)
                self._assert_retained_recovery_carrier(
                    error=exit_errors[0],
                    staged=staged,
                    helper=helper,
                    expected_refresh_token=self.SYNTH_REFRESH_B,
                )
                try:
                    release_candidate.set()
                    self.assertEqual(len(watchers), 1)
                    deadline = time.monotonic() + 3.0
                    while watchers[0].is_alive() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertFalse(watchers[0].is_alive())
                    self.assertFalse(background_writeback_called.is_set())
                    host = json.loads(source.read_text(encoding="utf-8"))
                    self.assertEqual(
                        host["claudeAiOauth"]["refreshToken"],
                        self.SYNTH_REFRESH_A,
                    )
                finally:
                    release_candidate.set()

    def test_timeout_reports_admitted_background_writeback_ambiguity(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            writeback_started = threading.Event()
            release_writeback = threading.Event()
            real_writeback = claude_linux._writeback_refreshed_credential_impl
            real_start = claude_linux._StagedCredentialWatcher.start
            watchers: list[claude_linux._StagedCredentialWatcher] = []

            def block_background_writeback(
                *args: object,
                **kwargs: object,
            ) -> object:
                if (
                    threading.current_thread().name
                    == "codex-claude-staged-credential-watcher"
                ):
                    writeback_started.set()
                    self.assertTrue(release_writeback.wait(timeout=5.0))
                return real_writeback(*args, **kwargs)

            def start_and_capture(
                watcher: claude_linux._StagedCredentialWatcher,
            ) -> None:
                watchers.append(watcher)
                real_start(watcher)

            with (
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_POLL_SECONDS",
                    0.01,
                ),
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_JOIN_TIMEOUT_SECONDS",
                    0.01,
                ),
                mock.patch.object(
                    claude_linux,
                    "_writeback_refreshed_credential_impl",
                    side_effect=block_background_writeback,
                ),
                mock.patch.object(
                    claude_linux._StagedCredentialWatcher,
                    "start",
                    autospec=True,
                    side_effect=start_and_capture,
                ),
            ):
                manager = claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                )
                staged = manager.__enter__()
                rotated = self._credential(
                    staged.config_dir / "in-flight-rotation.json",
                    expires_at_ms=(now + 7200) * 1000,
                    access_token=self.SYNTH_ACCESS_A,
                    refresh_token=self.SYNTH_REFRESH_B,
                )
                rotated.replace(staged.credential_path)
                self.assertTrue(writeback_started.wait(timeout=3.0))

                with self.assertRaisesRegex(
                    claude_linux.LinuxCredentialInspectionInconclusive,
                    "background host credential writeback was already in "
                    "flight.*host credential state is ambiguous",
                ) as raised:
                    manager.__exit__(None, None, None)

                self._assert_retained_recovery_carrier(
                    error=raised.exception,
                    staged=staged,
                    helper=helper,
                    expected_refresh_token=self.SYNTH_REFRESH_B,
                )
                self.assertTrue(
                    getattr(
                        raised.exception,
                        "_codex_claude_host_writeback_in_flight_at_stop",
                        False,
                    )
                )
                try:
                    release_writeback.set()
                    self.assertEqual(len(watchers), 1)
                    deadline = time.monotonic() + 3.0
                    while watchers[0].is_alive() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertFalse(watchers[0].is_alive())
                    host = json.loads(source.read_text(encoding="utf-8"))
                    self.assertEqual(
                        host["claudeAiOauth"]["refreshToken"],
                        self.SYNTH_REFRESH_B,
                    )
                finally:
                    release_writeback.set()

    def test_forwarded_signal_process_exit_retains_unproven_carrier(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            child = "\n".join(
                (
                    "import os, pathlib, signal, sys, threading, time",
                    "sys.path.insert(0, sys.argv[1])",
                    "from review_runtime import claude_linux, claude_refresh_lock",
                    "source = pathlib.Path(sys.argv[2])",
                    "helper = pathlib.Path(sys.argv[3])",
                    "started = threading.Event()",
                    "real_is_alive = claude_linux._StagedCredentialWatcher.is_alive",
                    "def forward_signal(signum, _frame):",
                    "    raise claude_linux.ForwardedSignal(signal.Signals(signum))",
                    "signal.signal(signal.SIGTERM, forward_signal)",
                    "def block_drain(self, *, final):",
                    "    if final:",
                    "        return",
                    "    started.set()",
                    "    time.sleep(0.2)",
                    "def signal_during_branch(self):",
                    "    result = real_is_alive(self)",
                    "    os.kill(os.getpid(), signal.SIGTERM)",
                    "    return result",
                    "claude_linux.STAGED_CREDENTIAL_POLL_SECONDS = 0.01",
                    "claude_linux.STAGED_CREDENTIAL_JOIN_TIMEOUT_SECONDS = 0.01",
                    "claude_linux._StagedCredentialWatcher._drain = block_drain",
                    "claude_linux._StagedCredentialWatcher.is_alive = signal_during_branch",
                    "try:",
                    "    with claude_linux.stage_claude_credentials(",
                    "        source,",
                    "        helper,",
                    "        required_validity_seconds=0.0,",
                    "        refresh_lock_protocol=claude_refresh_lock.CLAUDE_REFRESH_LOCK_PROTOCOL_2_1_211,",
                    "    ):",
                    "        if not started.wait(timeout=2.0):",
                    "            os._exit(91)",
                    "except claude_linux.ForwardedSignal as error:",
                    "    if error.signum != signal.SIGTERM:",
                    "        os._exit(92)",
                    "    retained = getattr(error, '_codex_claude_retained_credential_carrier', None)",
                    "    if not isinstance(retained, str):",
                    "        os._exit(93)",
                    "    if pathlib.Path(retained).parent.resolve() != helper.resolve():",
                    "        os._exit(94)",
                    "    remaining = list(helper.iterdir())",
                    "    if len(remaining) != 1 or not pathlib.Path(retained).samefile(remaining[0]):",
                    "        os._exit(95)",
                    "    if getattr(error, '_codex_claude_refresh_persistence_failed', None) is not True:",
                    "        os._exit(96)",
                    "    os._exit(23)",
                    "except claude_linux.LinuxCredentialInspectionInconclusive:",
                    "    os._exit(24)",
                    "os._exit(25)",
                )
            )

            completed = subprocess.run(
                (
                    sys.executable,
                    "-c",
                    child,
                    str(SCRIPTS),
                    str(source),
                    str(helper),
                ),
                check=False,
                capture_output=True,
                timeout=5.0,
            )

            self.assertEqual(completed.returncode, 23, completed.stderr.decode())
            remaining = list(helper.iterdir())
            self.assertEqual(len(remaining), 1)
            carrier = remaining[0]
            config = carrier / "config"
            credential = config / ".credentials.json"
            self.assertEqual(stat.S_IMODE(carrier.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(credential.stat().st_mode), 0o600)
            retained = json.loads(credential.read_text(encoding="utf-8"))
            self.assertEqual(
                retained["claudeAiOauth"]["refreshToken"],
                "not-a-real-token",
            )

    def test_interrupted_start_handoff_still_cleans_watcher(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            forwarded = claude_linux.ForwardedSignal(signal.SIGTERM)
            real_start = claude_linux._StagedCredentialWatcher.start
            thread_started = threading.Event()

            def start_then_interrupt(
                watcher: claude_linux._StagedCredentialWatcher,
            ) -> None:
                real_start(watcher)
                thread_started.set()
                raise forwarded

            with (
                mock.patch.object(
                    claude_linux._StagedCredentialWatcher,
                    "start",
                    autospec=True,
                    side_effect=start_then_interrupt,
                ),
                self.assertRaises(claude_linux.ForwardedSignal) as caught,
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ):
                    self.fail("an interrupted start must not yield a carrier")

            self.assertTrue(thread_started.is_set())
            self.assertIs(caught.exception, forwarded)
            self.assertFalse(
                any(
                    thread.name == "codex-claude-staged-credential-watcher"
                    and thread.is_alive()
                    for thread in threading.enumerate()
                )
            )
            self.assertEqual(list(helper.iterdir()), [])

    def test_final_drain_recovers_after_ordinary_watcher_failure(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            fail_worker_read = threading.Event()
            fail_worker_read.set()
            worker_attempted = threading.Event()
            worker_failure_recorded = threading.Event()
            real_read = claude_linux._read_staged_credential_under_lock
            real_record = claude_linux._StagedCredentialWatcher._record_worker_failure

            def fail_then_recover(*args: object, **kwargs: object):
                if fail_worker_read.is_set():
                    worker_attempted.set()
                    raise OSError("injected transient watcher failure")
                return real_read(*args, **kwargs)

            def record_failure(
                watcher: claude_linux._StagedCredentialWatcher,
                error: BaseException,
            ) -> None:
                real_record(watcher, error)
                worker_failure_recorded.set()

            with (
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_POLL_SECONDS",
                    0.01,
                ),
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_RETRY_SECONDS",
                    0.0,
                ),
                mock.patch.object(
                    claude_linux,
                    "_read_staged_credential_under_lock",
                    side_effect=fail_then_recover,
                ),
                mock.patch.object(
                    claude_linux._StagedCredentialWatcher,
                    "_record_worker_failure",
                    autospec=True,
                    side_effect=record_failure,
                ),
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ) as staged:
                    rotated = self._credential(
                        staged.config_dir / "recovered.json",
                        expires_at_ms=(now + 7200) * 1000,
                        access_token=self.SYNTH_ACCESS_A,
                        refresh_token=self.SYNTH_REFRESH_B,
                    )
                    rotated.replace(staged.credential_path)
                    self.assertTrue(worker_attempted.wait(timeout=3.0))
                    self.assertTrue(worker_failure_recorded.wait(timeout=3.0))
                    fail_worker_read.clear()

            value = json.loads(source.read_text(encoding="utf-8"))
            self.assertEqual(
                value["claudeAiOauth"]["refreshToken"],
                self.SYNTH_REFRESH_B,
            )
            self.assertEqual(list(helper.iterdir()), [])

    def test_staged_read_combines_operation_error_with_visible_lock_paths(
        self,
    ) -> None:
        lock_path = pathlib.Path("/fixture/claude-carrier/config/.oauth_refresh.lock")
        cleanup_error = claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive(
            "injected refresh-lock cleanup timeout"
        )
        setattr(
            cleanup_error,
            "_codex_claude_refresh_lock_paths",
            (str(lock_path),),
        )
        refresh_lock = mock.Mock(spec=["release"])
        refresh_lock.release.side_effect = cleanup_error
        operation_error = claude_linux.LinuxCredentialUnsafe(
            "injected staged credential read failure"
        )
        staged = claude_linux.StagedCredential(
            lock_path.parents[1],
            lock_path.parent,
            lock_path.parent / ".credentials.json",
            0.0,
        )

        with (
            mock.patch.object(
                claude_linux,
                "acquire_claude_refresh_lock",
                return_value=refresh_lock,
            ),
            mock.patch.object(
                claude_linux,
                "_read_valid_credential",
                side_effect=operation_error,
            ),
            self.assertRaises(claude_linux.LinuxCredentialUnsafe) as raised,
        ):
            claude_linux._read_staged_credential_under_lock(
                staged,
                owner_uid=os.getuid(),
                refresh_lock_protocol=self.PROTOCOL,
                timeout_seconds=0,
            )

        self.assertIs(raised.exception, operation_error)
        self.assertIn(str(lock_path), str(raised.exception))
        self.assertEqual(
            getattr(
                raised.exception,
                "_codex_claude_refresh_lock_paths",
            ),
            (str(lock_path),),
        )

    def test_writeback_wrapper_preserves_combined_refresh_lock_paths(
        self,
    ) -> None:
        lock_path = pathlib.Path("/fixture/claude-carrier/config/.oauth_refresh.lock")
        cleanup_error = claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive(
            "injected refresh-lock cleanup timeout"
        )
        setattr(
            cleanup_error,
            "_codex_claude_refresh_lock_paths",
            (str(lock_path),),
        )
        operation_error = OSError(5, "injected writeback failure")
        combined = claude_linux._primary_cleanup_error([operation_error, cleanup_error])
        self.assertIs(combined, operation_error)
        staged = claude_linux.StagedCredential(
            lock_path.parents[1],
            lock_path.parent,
            lock_path.parent / ".credentials.json",
            0.0,
        )

        with (
            mock.patch.object(
                claude_linux,
                "_writeback_refreshed_credential_impl",
                side_effect=operation_error,
            ),
            self.assertRaises(
                claude_linux.LinuxCredentialInspectionInconclusive
            ) as raised,
        ):
            claude_linux._writeback_refreshed_credential(
                pathlib.Path("/fixture/.credentials.json"),
                mock.Mock(),
                staged,
                bytearray(b"{}"),
                mock.Mock(),
                mock.Mock(),
                owner_uid=os.getuid(),
                refresh_lock_protocol=self.PROTOCOL,
            )

        self.assertIn(str(lock_path), str(raised.exception))
        self.assertEqual(
            getattr(
                raised.exception,
                "_codex_claude_refresh_lock_paths",
            ),
            (str(lock_path),),
        )

    def test_watcher_control_flow_overrides_ordinary_body_failure(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )

            with (
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_POLL_SECONDS",
                    60.0,
                ),
                mock.patch.object(
                    claude_linux,
                    "_writeback_refreshed_credential_impl",
                    side_effect=KeyboardInterrupt,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ):
                    raise ValueError("injected ordinary body failure")

            self.assertEqual(list(helper.iterdir()), [])

    def test_forwarded_signal_overrides_ordinary_body_failure(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            forwarded = claude_linux.ForwardedSignal(signal.SIGTERM)
            worker_failure_recorded = threading.Event()
            real_record = claude_linux._StagedCredentialWatcher._record_worker_failure

            def record_failure(
                watcher: claude_linux._StagedCredentialWatcher,
                error: BaseException,
            ) -> None:
                real_record(watcher, error)
                worker_failure_recorded.set()

            with (
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_POLL_SECONDS",
                    0.01,
                ),
                mock.patch.object(
                    claude_linux,
                    "_writeback_refreshed_credential_impl",
                    side_effect=forwarded,
                ),
                mock.patch.object(
                    claude_linux._StagedCredentialWatcher,
                    "_record_worker_failure",
                    autospec=True,
                    side_effect=record_failure,
                ),
                self.assertRaises(claude_linux.ForwardedSignal) as caught,
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ) as staged:
                    rotated = self._credential(
                        staged.config_dir / "rotated.json",
                        expires_at_ms=(now + 7200) * 1000,
                        access_token=self.SYNTH_ACCESS_A,
                        refresh_token=self.SYNTH_REFRESH_B,
                    )
                    rotated.replace(staged.credential_path)
                    self.assertTrue(worker_failure_recorded.wait(timeout=3.0))
                    raise ValueError("injected ordinary body failure")

            self.assertIs(caught.exception, forwarded)
            self.assertEqual(caught.exception.signum, signal.SIGTERM)
            self._assert_retained_recovery_carrier(
                error=caught.exception,
                staged=staged,
                helper=helper,
                expected_refresh_token=self.SYNTH_REFRESH_B,
            )

    def test_body_control_flow_precedes_deferred_cleanup_signal(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )

            with (
                mock.patch.object(
                    claude_linux,
                    "block_forwarded_signals",
                    return_value=set(),
                ),
                mock.patch.object(
                    claude_linux,
                    "consume_pending_forwarded_signal",
                    return_value=signal.SIGTERM,
                ),
                mock.patch.object(claude_linux, "restore_signal_mask"),
                self.assertRaises(KeyboardInterrupt) as caught,
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                ):
                    raise KeyboardInterrupt

            notes = getattr(caught.exception, "__notes__", ())
            if notes:
                self.assertTrue(any("ForwardedSignal" in note for note in notes))
            else:
                diagnostic = caught.exception.__cause__
                self.assertIsInstance(
                    diagnostic,
                    claude_linux.LinuxCredentialCleanupDiagnostic,
                )
                assert diagnostic is not None
                self.assertIn("ForwardedSignal", str(diagnostic))
            self.assertEqual(list(helper.iterdir()), [])

    def test_deferred_signal_preserves_cleanup_failure_diagnostic(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            real_cleanup = claude_linux._cleanup_staged_credential

            def cleanup_then_report(
                staged: claude_linux.StagedCredential,
            ) -> BaseException:
                cleanup_error = real_cleanup(staged)
                self.assertIsNone(cleanup_error)
                return claude_linux.LinuxCredentialInspectionInconclusive(
                    "injected cleanup diagnostic"
                )

            with (
                mock.patch.object(
                    claude_linux,
                    "block_forwarded_signals",
                    return_value=set(),
                ),
                mock.patch.object(
                    claude_linux,
                    "consume_pending_forwarded_signal",
                    return_value=signal.SIGTERM,
                ),
                mock.patch.object(claude_linux, "restore_signal_mask"),
                mock.patch.object(
                    claude_linux,
                    "_cleanup_staged_credential",
                    side_effect=cleanup_then_report,
                ),
                self.assertRaises(claude_linux.ForwardedSignal) as caught,
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                ):
                    pass

            self.assertEqual(caught.exception.signum, signal.SIGTERM)
            notes = getattr(caught.exception, "__notes__", ())
            if notes:
                self.assertTrue(
                    any("injected cleanup diagnostic" in note for note in notes)
                )
            else:
                diagnostic = caught.exception.__cause__
                self.assertIsInstance(
                    diagnostic,
                    claude_linux.LinuxCredentialCleanupDiagnostic,
                )
                assert diagnostic is not None
                self.assertIn("injected cleanup diagnostic", str(diagnostic))
            self.assertEqual(list(helper.iterdir()), [])

    def test_persistent_watcher_inspection_failure_is_inconclusive(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )

            with (
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_RETRY_SECONDS",
                    0.0,
                ),
                mock.patch.object(
                    claude_linux,
                    "_read_staged_credential_under_lock",
                    side_effect=OSError("injected staged inspection failure"),
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialInspectionInconclusive,
                    "remained unstable",
                ),
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ):
                    pass

            self.assertEqual(list(helper.iterdir()), [])

    def test_compromised_claude_refresh_lock_blocks_writeback(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            original_payload = source.read_bytes()
            staged_refresh_lock = mock.Mock(spec=["release"])
            host_refresh_lock = mock.Mock(spec=["assert_held", "release"])
            host_refresh_lock.assert_held.side_effect = (
                claude_linux.ClaudeRefreshLockError("fixture lock compromise")
            )

            with (
                mock.patch.object(
                    claude_linux,
                    "acquire_claude_refresh_lock",
                    side_effect=[staged_refresh_lock, host_refresh_lock],
                ) as acquire_refresh_lock,
                mock.patch.object(
                    claude_linux,
                    "STAGED_CREDENTIAL_POLL_SECONDS",
                    60.0,
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialInspectionInconclusive,
                    "refresh lock changed",
                ) as raised,
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ) as staged:
                    self._credential(
                        staged.credential_path,
                        expires_at_ms=(now + 7200) * 1000,
                        access_token=self.SYNTH_ACCESS_A,
                        refresh_token=self.SYNTH_REFRESH_B,
                    )

            staged_refresh_lock.release.assert_called_once_with()
            host_refresh_lock.release.assert_called_once_with()
            self.assertEqual(
                acquire_refresh_lock.call_args_list,
                [
                    mock.call(
                        staged.config_dir,
                        protocol=self.PROTOCOL,
                        timeout_seconds=(
                            claude_linux.STAGED_CREDENTIAL_LOCK_TIMEOUT_SECONDS
                        ),
                    ),
                    mock.call(
                        source.parent,
                        protocol=self.PROTOCOL,
                        config_dir_fd=mock.ANY,
                        legacy_parent_dir_fd=mock.ANY,
                    ),
                ],
            )
            self.assertEqual(source.read_bytes(), original_payload)
            self._assert_retained_recovery_carrier(
                error=raised.exception,
                staged=staged,
                helper=helper,
                expected_refresh_token=self.SYNTH_REFRESH_B,
            )

    def test_malformed_staged_update_does_not_replace_source(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            original_payload = source.read_bytes()

            with self.assertRaisesRegex(
                claude_linux.LinuxCredentialUnsafe,
                "staged credential update",
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                ) as staged:
                    staged.credential_path.write_text("{", encoding="utf-8")

            self.assertEqual(source.read_bytes(), original_payload)
            self.assertEqual(list(helper.iterdir()), [])

    def test_surrogate_staged_update_does_not_replace_source(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            original_payload = source.read_bytes()

            with self.assertRaisesRegex(
                claude_linux.LinuxCredentialUnsafe,
                "staged credential update",
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                ) as staged:
                    staged.credential_path.write_bytes(
                        b'{"claudeAiOauth":{"accessToken":"a",'
                        b'"refreshToken":"\\ud800","expiresAt":1}}'
                    )

            self.assertEqual(source.read_bytes(), original_payload)
            self.assertEqual(list(helper.iterdir()), [])

    def test_expired_access_with_rotated_refresh_token_is_persisted(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 120) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            with claude_linux.stage_claude_credentials(
                source,
                helper,
                now=now,
                refresh_lock_protocol=self.PROTOCOL,
            ) as staged:
                self._credential(
                    staged.credential_path,
                    expires_at_ms=(now - 60) * 1000,
                    access_token=self.SYNTH_ACCESS_A,
                    refresh_token=self.SYNTH_REFRESH_B,
                )

            persisted = json.loads(source.read_text(encoding="utf-8"))
            oauth = persisted["claudeAiOauth"]
            self.assertEqual(oauth["accessToken"], self.SYNTH_ACCESS_A)
            self.assertEqual(oauth["refreshToken"], self.SYNTH_REFRESH_B)
            self.assertEqual(list(helper.iterdir()), [])

    def test_atomic_replace_failure_keeps_source_and_recovery_candidate(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            original_payload = source.read_bytes()

            with (
                mock.patch.object(
                    claude_linux.os,
                    "replace",
                    side_effect=OSError("injected atomic replace failure"),
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialInspectionInconclusive,
                    "atomically replace",
                ) as raised,
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ) as staged:
                    self._credential(
                        staged.credential_path,
                        expires_at_ms=(now + 7200) * 1000,
                        access_token=self.SYNTH_ACCESS_A,
                        refresh_token=self.SYNTH_REFRESH_B,
                    )

            self.assertEqual(source.read_bytes(), original_payload)
            self.assertEqual(
                list(root.glob("..credentials.json.codex-review-*")),
                [],
            )
            self._assert_retained_recovery_carrier(
                error=raised.exception,
                staged=staged,
                helper=helper,
                expected_refresh_token=self.SYNTH_REFRESH_B,
            )

    def test_writeback_error_remains_primary_when_cleanup_also_fails(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            staged_path: pathlib.Path | None = None
            staged_dir: pathlib.Path | None = None

            with (
                mock.patch.object(
                    pathlib.Path,
                    "unlink",
                    side_effect=OSError("injected cleanup unlink failure"),
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialUnsafe,
                    "staged credential update",
                ) as raised,
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                ) as staged:
                    staged_path = staged.credential_path
                    staged_dir = staged.config_dir
                    staged.credential_path.write_text("{", encoding="utf-8")

            notes = getattr(raised.exception, "__notes__", ())
            if notes:
                self.assertTrue(any("cleanup" in note.lower() for note in notes))
            else:
                self.assertIsNotNone(raised.exception.__cause__)
                assert raised.exception.__cause__ is not None
                self.assertIn("cleanup", str(raised.exception.__cause__).lower())
            assert staged_path is not None
            assert staged_dir is not None
            carrier_root = staged_dir.parent
            staged_path.unlink()
            staged_dir.rmdir()
            carrier_root.rmdir()

    def test_cleanup_interruption_overrides_writeback_error(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            staged_path: pathlib.Path | None = None
            staged_dir: pathlib.Path | None = None

            with (
                mock.patch.object(
                    pathlib.Path,
                    "unlink",
                    side_effect=KeyboardInterrupt,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                ) as staged:
                    staged_path = staged.credential_path
                    staged_dir = staged.config_dir
                    staged.credential_path.write_text("{", encoding="utf-8")

            assert staged_path is not None
            assert staged_dir is not None
            carrier_root = staged_dir.parent
            staged_path.unlink()
            staged_dir.rmdir()
            carrier_root.rmdir()

    def test_writeback_interruption_overrides_ordinary_body_error(self) -> None:
        now = time.time()
        marker = KeyboardInterrupt("injected writeback interruption")
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            manager = claude_linux.stage_claude_credentials(
                source,
                helper,
                now=now,
                refresh_lock_protocol=self.PROTOCOL,
            )
            manager.__enter__()
            body_error = ValueError("injected body failure")

            with (
                mock.patch.object(
                    claude_linux,
                    "_writeback_refreshed_credential",
                    side_effect=marker,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                manager.__exit__(ValueError, body_error, None)

            self.assertIs(raised.exception, marker)
            self.assertEqual(list(helper.iterdir()), [])

    def test_cleanup_note_is_visible_on_python_310_fallback(self) -> None:
        class LegacyError(FileNotFoundError):
            add_note = None

        body_error = LegacyError(2, "missing", "/tmp/test-only")
        cleanup_error = OSError("cleanup failed")
        previous_cause = ValueError("previous cause")
        body_error.__cause__ = previous_cause

        claude_linux._add_cleanup_note(body_error, cleanup_error)

        diagnostic = body_error.__cause__
        self.assertIsInstance(
            diagnostic,
            claude_linux.LinuxCredentialCleanupDiagnostic,
        )
        assert diagnostic is not None
        self.assertIn("credential cleanup also failed", str(diagnostic).lower())
        self.assertIn("cleanup failed", str(diagnostic))
        self.assertIs(diagnostic.__cause__, previous_cause)

    def test_source_close_failure_zeroes_successful_read(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            source = self._credential(
                pathlib.Path(temporary) / ".credentials.json",
                expires_at_ms=(now + 7200) * 1000,
            )
            captured_payloads: list[bytearray] = []
            real_loads = json.loads

            def capture_loads(
                payload: bytearray,
                *args: object,
                **kwargs: object,
            ) -> object:
                captured_payloads.append(payload)
                return real_loads(payload, *args, **kwargs)

            with (
                mock.patch.object(
                    claude_linux.json,
                    "loads",
                    side_effect=capture_loads,
                ),
                mock.patch.object(
                    claude_linux.os,
                    "close",
                    side_effect=OSError("injected source close failure"),
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialInspectionInconclusive,
                    "cannot close Claude credential source",
                ),
            ):
                claude_linux._read_valid_credential(
                    source,
                    owner_uid=os.getuid(),
                    now=now,
                    required_validity_seconds=3600,
                )

            self.assertEqual(len(captured_payloads), 1)
            self.assertEqual(set(captured_payloads[0]), {0})

    @unittest.skipUnless(
        hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
        "requires POSIX FIFO support",
    )
    def test_source_reader_rejects_fifo_without_blocking(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            source = pathlib.Path(temporary) / ".credentials.json"
            os.mkfifo(source, mode=0o600)
            requested_flags: list[int] = []
            real_open = os.open

            def guarded_open(
                path: os.PathLike[str] | str,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                requested_flags.append(flags)
                return real_open(path, flags | os.O_NONBLOCK, *args, **kwargs)

            with (
                mock.patch.object(
                    claude_linux.os,
                    "open",
                    side_effect=guarded_open,
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialUnsafe,
                    "not a regular file",
                ),
            ):
                claude_linux._read_valid_credential(
                    source,
                    owner_uid=os.getuid(),
                    now=now,
                    required_validity_seconds=3600,
                )

            self.assertEqual(len(requested_flags), 1)
            self.assertTrue(requested_flags[0] & os.O_NONBLOCK)

    def test_source_close_failure_does_not_mask_validation_error(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            source = self._credential(
                pathlib.Path(temporary) / ".credentials.json",
                expires_at_ms=(now + 7200) * 1000,
            )
            source.chmod(0o644)

            with (
                mock.patch.object(
                    claude_linux.os,
                    "close",
                    side_effect=OSError("injected source close failure"),
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialUnsafe,
                    "mode must be exactly 0600",
                ) as raised,
            ):
                claude_linux._read_valid_credential(
                    source,
                    owner_uid=os.getuid(),
                    now=now,
                    required_validity_seconds=3600,
                )

            notes = getattr(raised.exception, "__notes__", ())
            if notes:
                self.assertTrue(
                    any("source close failure" in note for note in notes),
                    notes,
                )
            else:
                diagnostic = raised.exception.__cause__
                self.assertIsInstance(
                    diagnostic,
                    claude_linux.LinuxCredentialCleanupDiagnostic,
                )
                assert diagnostic is not None
                self.assertIn("source close failure", str(diagnostic))

    def test_source_close_interruption_remains_control_flow(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            source = self._credential(
                pathlib.Path(temporary) / ".credentials.json",
                expires_at_ms=(now + 7200) * 1000,
            )

            with (
                mock.patch.object(
                    claude_linux.os,
                    "close",
                    side_effect=KeyboardInterrupt,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                claude_linux._read_valid_credential(
                    source,
                    owner_uid=os.getuid(),
                    now=now,
                    required_validity_seconds=3600,
                )

    def test_staged_read_oserror_remains_inspection_inconclusive(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            original = source.read_bytes()
            manager = claude_linux.stage_claude_credentials(
                source,
                helper,
                now=now,
                refresh_lock_protocol=self.PROTOCOL,
            )
            manager.__enter__()

            with (
                mock.patch.object(
                    claude_linux.os,
                    "read",
                    side_effect=OSError("injected staged read failure"),
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialInspectionInconclusive,
                    "cannot read Claude credential source",
                ),
            ):
                manager.__exit__(None, None, None)

            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(list(helper.iterdir()), [])

    def test_transient_staged_close_oserror_is_retried(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            original = source.read_bytes()
            manager = claude_linux.stage_claude_credentials(
                source,
                helper,
                now=now,
                refresh_lock_protocol=self.PROTOCOL,
            )
            manager.__enter__()
            real_close = os.close
            failed = False

            def close_then_fail_once(descriptor: int) -> None:
                nonlocal failed
                real_close(descriptor)
                if not failed:
                    failed = True
                    raise OSError("injected staged close failure")

            with mock.patch.object(
                claude_linux.os,
                "close",
                side_effect=close_then_fail_once,
            ):
                manager.__exit__(None, None, None)

            self.assertTrue(failed)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(list(helper.iterdir()), [])

    def test_removes_partial_credential_after_write_failure(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json", expires_at_ms=(now + 7200) * 1000
            )
            real_write = os.write
            writes = 0

            def fail_after_partial_write(fd: int, payload: bytes) -> int:
                nonlocal writes
                writes += 1
                if writes == 1:
                    return real_write(fd, payload[:8])
                raise OSError("injected write failure")

            with (
                mock.patch.object(
                    claude_linux.os,
                    "write",
                    side_effect=fail_after_partial_write,
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialInspectionInconclusive,
                    "cannot write staged Claude credential",
                ),
            ):
                with claude_linux.stage_claude_credentials(source, helper, now=now):
                    pass

            self.assertEqual(list(helper.iterdir()), [])

    def test_removes_partial_credential_after_write_interruption(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json", expires_at_ms=(now + 7200) * 1000
            )
            real_write = os.write
            writes = 0

            def interrupt_after_partial_write(fd: int, payload: bytes) -> int:
                nonlocal writes
                writes += 1
                if writes == 1:
                    return real_write(fd, payload[:8])
                raise KeyboardInterrupt

            with (
                mock.patch.object(
                    claude_linux.os,
                    "write",
                    side_effect=interrupt_after_partial_write,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                with claude_linux.stage_claude_credentials(source, helper, now=now):
                    pass

            self.assertEqual(list(helper.iterdir()), [])

    def test_removes_complete_credential_after_close_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / ".credentials.json"
            payload = bytearray(b"test-only credential payload")
            real_close = os.close
            closes = 0

            def close_then_fail(fd: int) -> None:
                nonlocal closes
                closes += 1
                real_close(fd)
                if closes == 1:
                    raise OSError("injected close failure")

            with (
                mock.patch.object(
                    claude_linux.os,
                    "close",
                    side_effect=close_then_fail,
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialInspectionInconclusive,
                    "cannot close staged Claude credential",
                ),
            ):
                claude_linux._write_private_file(path, payload)

            self.assertFalse(path.exists())

    def test_removes_partial_credential_after_finalize_failure(self) -> None:
        now = time.time()
        for operation in ("fsync", "fchmod"):
            with (
                self.subTest(operation=operation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = pathlib.Path(temporary)
                helper = root / "helper"
                helper.mkdir(mode=0o700)
                source = self._credential(
                    root / ".credentials.json", expires_at_ms=(now + 7200) * 1000
                )

                with (
                    mock.patch.object(
                        claude_linux.os,
                        operation,
                        side_effect=OSError(f"injected {operation} failure"),
                    ),
                    self.assertRaisesRegex(
                        claude_linux.LinuxCredentialInspectionInconclusive,
                        "cannot finalize staged Claude credential",
                    ),
                ):
                    with claude_linux.stage_claude_credentials(
                        source,
                        helper,
                        now=now,
                    ):
                        pass

                self.assertEqual(list(helper.iterdir()), [])

    def test_zeroes_partial_credential_when_unlink_fails(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json", expires_at_ms=(now + 7200) * 1000
            )

            with (
                mock.patch.object(
                    claude_linux.os,
                    "fchmod",
                    side_effect=OSError("injected finalize failure"),
                ),
                mock.patch.object(
                    pathlib.Path,
                    "unlink",
                    side_effect=OSError("injected unlink failure"),
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialInspectionInconclusive,
                    "cannot remove partial staged Claude credential",
                ),
            ):
                with claude_linux.stage_claude_credentials(source, helper, now=now):
                    pass

            staged_directories = list(helper.iterdir())
            self.assertEqual(len(staged_directories), 1)
            staged_config = staged_directories[0] / "config"
            staged_credential = staged_config / ".credentials.json"
            self.assertGreater(staged_credential.stat().st_size, 0)
            self.assertEqual(set(staged_credential.read_bytes()), {0})
            staged_credential.unlink()
            staged_config.rmdir()
            staged_directories[0].rmdir()

    def test_cleanup_preserves_body_exception_when_close_fails(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json", expires_at_ms=(now + 7200) * 1000
            )
            real_close = os.close
            close_patch = None
            closes = 0
            staged_dir: pathlib.Path | None = None

            def close_then_fail(fd: int) -> None:
                nonlocal closes
                closes += 1
                real_close(fd)
                if closes == 1:
                    raise OSError("injected cleanup close failure")

            try:
                with self.assertRaisesRegex(ValueError, "injected body failure"):
                    with claude_linux.stage_claude_credentials(
                        source,
                        helper,
                        now=now,
                    ) as staged:
                        staged_dir = staged.config_dir
                        close_patch = mock.patch.object(
                            claude_linux.os,
                            "close",
                            side_effect=close_then_fail,
                        )
                        close_patch.start()
                        raise ValueError("injected body failure")
            finally:
                if close_patch is not None:
                    close_patch.stop()

            assert staged_dir is not None
            self.assertFalse(staged_dir.exists())

    def test_generator_close_unlinks_after_scrub_interruption(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json", expires_at_ms=(now + 7200) * 1000
            )
            manager = claude_linux.stage_claude_credentials(source, helper, now=now)
            staged = manager.__enter__()

            with mock.patch.object(
                claude_linux.os,
                "write",
                side_effect=KeyboardInterrupt,
            ):
                manager.gen.close()

            self.assertFalse(staged.config_dir.exists())

    def test_normal_cleanup_rethrows_scrub_interruption_after_unlink(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json", expires_at_ms=(now + 7200) * 1000
            )
            manager = claude_linux.stage_claude_credentials(source, helper, now=now)
            staged = manager.__enter__()

            with (
                mock.patch.object(
                    claude_linux.os,
                    "write",
                    side_effect=KeyboardInterrupt,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                manager.__exit__(None, None, None)

            self.assertFalse(staged.config_dir.exists())

    def test_normal_cleanup_preserves_unlink_interruption(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json", expires_at_ms=(now + 7200) * 1000
            )
            manager = claude_linux.stage_claude_credentials(source, helper, now=now)
            staged = manager.__enter__()

            with (
                mock.patch.object(
                    pathlib.Path,
                    "unlink",
                    side_effect=KeyboardInterrupt,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                manager.__exit__(None, None, None)

            self.assertTrue(staged.credential_path.exists())
            staged.credential_path.unlink()
            staged.config_dir.rmdir()

    def test_cleanup_interruption_overrides_ordinary_body_error(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json", expires_at_ms=(now + 7200) * 1000
            )

            manager = claude_linux.stage_claude_credentials(
                source,
                helper,
                now=now,
            )
            manager.__enter__()
            body_error = ValueError("injected body failure")
            with (
                mock.patch.object(
                    claude_linux.os,
                    "write",
                    side_effect=KeyboardInterrupt,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                manager.__exit__(ValueError, body_error, None)

            self.assertEqual(list(helper.iterdir()), [])

    @unittest.skipUnless(
        hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
        "requires POSIX FIFO support",
    )
    def test_private_file_cleanup_unlinks_fifo_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / ".credentials.json"
            os.mkfifo(path, mode=0o600)
            requested_flags: list[int] = []
            real_open = os.open

            def guarded_open(
                target: os.PathLike[str] | str,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                requested_flags.append(flags)
                return real_open(target, flags | os.O_NONBLOCK, *args, **kwargs)

            with mock.patch.object(
                claude_linux.os,
                "open",
                side_effect=guarded_open,
            ):
                cleanup_error = claude_linux._discard_private_file(path, None)

            self.assertIsNone(cleanup_error)
            self.assertFalse(path.exists())
            self.assertEqual(len(requested_flags), 1)
            self.assertTrue(requested_flags[0] & os.O_NONBLOCK)

    @unittest.skipUnless(
        hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
        "requires POSIX FIFO support",
    )
    def test_private_file_at_cleanup_unlinks_fifo_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            name = ".credentials.json"
            path = root / name
            os.mkfifo(path, mode=0o600)
            parent_fd = os.open(
                root,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            requested_flags: list[int] = []
            real_open = os.open

            def guarded_open(
                target: os.PathLike[str] | str,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                requested_flags.append(flags)
                return real_open(target, flags | os.O_NONBLOCK, *args, **kwargs)

            try:
                with mock.patch.object(
                    claude_linux.os,
                    "open",
                    side_effect=guarded_open,
                ):
                    cleanup_error = claude_linux._discard_private_file_at(
                        parent_fd,
                        name,
                        None,
                    )
            finally:
                os.close(parent_fd)

            self.assertIsInstance(cleanup_error, OSError)
            self.assertFalse(path.exists())
            self.assertEqual(len(requested_flags), 1)
            self.assertTrue(requested_flags[0] & os.O_NONBLOCK)

    def test_unlink_failure_is_primary_after_scrub_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / ".credentials.json"
            path.write_bytes(b"test-only credential payload")
            path.chmod(0o600)
            unlink_error = OSError("injected unlink failure")

            with (
                mock.patch.object(
                    claude_linux.os,
                    "fsync",
                    side_effect=OSError("injected scrub failure"),
                ),
                mock.patch.object(
                    pathlib.Path,
                    "unlink",
                    side_effect=unlink_error,
                ),
            ):
                cleanup_error = claude_linux._discard_private_file(path, None)

            self.assertIs(cleanup_error, unlink_error)
            path.unlink()

    def test_accepts_expired_but_rejects_permissive_and_symlink_credentials(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            stale = self._credential(
                root / "stale.json", expires_at_ms=(now - 60) * 1000
            )
            permissive = self._credential(
                root / "permissive.json", expires_at_ms=(now + 7200) * 1000
            )
            permissive.chmod(0o644)
            target = self._credential(
                root / "target.json", expires_at_ms=(now + 7200) * 1000
            )
            symlink = root / "link.json"
            symlink.symlink_to(target)
            hardlinked = self._credential(
                root / "hardlinked.json", expires_at_ms=(now + 7200) * 1000
            )
            os.link(hardlinked, root / "hardlinked-alias.json")

            with claude_linux.stage_claude_credentials(
                stale,
                helper,
                now=now,
                required_validity_seconds=3600,
            ):
                pass
            with self.assertRaisesRegex(claude_linux.LinuxCredentialUnsafe, "0600"):
                with claude_linux.stage_claude_credentials(permissive, helper, now=now):
                    pass
            with self.assertRaisesRegex(
                claude_linux.LinuxCredentialUnsafe,
                "must not be a symlink",
            ):
                with claude_linux.stage_claude_credentials(symlink, helper, now=now):
                    pass
            with self.assertRaisesRegex(
                claude_linux.LinuxCredentialUnsafe,
                "exactly one link",
            ):
                with claude_linux.stage_claude_credentials(
                    hardlinked,
                    helper,
                    now=now,
                ):
                    pass

    def test_classifies_missing_login_as_unavailable_and_malformed_as_unsafe(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            missing_token = root / "missing-token.json"
            missing_token.write_text(
                json.dumps({"claudeAiOauth": {"expiresAt": (now + 7200) * 1000}}),
                encoding="utf-8",
            )
            missing_token.chmod(0o600)
            missing_refresh = root / "missing-refresh.json"
            missing_refresh.write_text(
                json.dumps(
                    {
                        "claudeAiOauth": {
                            "accessToken": "not-a-real-token",
                            "expiresAt": (now + 7200) * 1000,
                        }
                    }
                ),
                encoding="utf-8",
            )
            missing_refresh.chmod(0o600)
            malformed = root / "malformed.json"
            malformed.write_text("{", encoding="utf-8")
            malformed.chmod(0o600)
            malformed_oauth = root / "malformed-oauth.json"
            malformed_oauth.write_text(
                json.dumps({"claudeAiOauth": []}),
                encoding="utf-8",
            )
            malformed_oauth.chmod(0o600)

            with self.assertRaises(claude_linux.LinuxCredentialUnavailable):
                with claude_linux.stage_claude_credentials(
                    root / "absent.json", helper, now=now
                ):
                    pass
            with self.assertRaisesRegex(
                claude_linux.LinuxCredentialUnavailable,
                "credential directory is unavailable",
            ):
                with claude_linux.stage_claude_credentials(
                    root / "missing-parent" / ".credentials.json",
                    helper,
                    now=now,
                ):
                    pass
            with self.assertRaises(claude_linux.LinuxCredentialUnavailable):
                with claude_linux.stage_claude_credentials(
                    missing_token, helper, now=now
                ):
                    pass
            with self.assertRaisesRegex(
                claude_linux.LinuxCredentialUnavailable,
                "refresh token",
            ):
                with claude_linux.stage_claude_credentials(
                    missing_refresh,
                    helper,
                    now=now,
                ):
                    pass
            with self.assertRaises(claude_linux.LinuxCredentialUnsafe):
                with claude_linux.stage_claude_credentials(malformed, helper, now=now):
                    pass
            with self.assertRaisesRegex(
                claude_linux.LinuxCredentialUnsafe,
                "JSON is malformed",
            ):
                with claude_linux.stage_claude_credentials(
                    malformed_oauth,
                    helper,
                    now=now,
                ):
                    pass

    def test_deeply_nested_credential_is_malformed(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            nested = root / "deeply-nested.json"
            depth = 10_000
            nested.write_bytes(
                b'{"claudeAiOauth":' + b"[" * depth + b"0" + b"]" * depth + b"}"
            )
            nested.chmod(0o600)

            with self.assertRaisesRegex(
                claude_linux.LinuxCredentialUnsafe,
                "JSON is malformed",
            ):
                with claude_linux.stage_claude_credentials(
                    nested,
                    helper,
                    now=now,
                ):
                    pass

            self.assertEqual(list(helper.iterdir()), [])

    def test_unpaired_surrogate_token_is_unsafe(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            credential = root / "surrogate-token.json"
            credential.write_bytes(
                b'{"claudeAiOauth":{"accessToken":"a",'
                b'"refreshToken":"\\ud800","expiresAt":1}}'
            )
            credential.chmod(0o600)

            with self.assertRaisesRegex(
                claude_linux.LinuxCredentialUnsafe,
                "token encoding is malformed",
            ):
                with claude_linux.stage_claude_credentials(
                    credential,
                    helper,
                    now=now,
                ):
                    pass

            self.assertEqual(list(helper.iterdir()), [])


class SandboxCommandTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = pathlib.Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        (self.workspace / "README.md").write_text("probe\n", encoding="utf-8")
        self.helper = self.root / "helper"
        self.helper.mkdir(mode=0o700)
        self.home = self.helper / "home"
        self.tmp = self.helper / "tmp"
        self.config_root = self.helper / "auth-carrier"
        self.config = self.config_root / "config"
        for directory in (self.home, self.tmp, self.config_root, self.config):
            directory.mkdir(mode=0o700)
        self.proxy_path = self.helper / "proxy.sock"
        self.proxy_path.touch()
        self.proxy_path.chmod(0o600)
        self.socket_validation = mock.patch.object(
            claude_linux,
            "_validate_private_socket",
            return_value=self.proxy_path.resolve(),
        )
        self.socket_validation.start()
        self.claude = _write_elf(self.root / "claude")
        self.launcher = _write_elf(self.helper / "launcher")
        self.tools = claude_linux.NativeToolchain(
            _write_elf(self.root / "bwrap"),
            _write_elf(self.root / "socat"),
            _write_elf(self.root / "rg"),
            _write_elf(self.root / "cc"),
        )
        self.library = next(
            path.resolve(strict=True)
            for path in (pathlib.Path("/usr/bin/env"), pathlib.Path("/bin/true"))
            if path.exists()
        )
        library_identity = claude_linux._capture_trusted_path_identity(self.library)
        self.host = claude_linux.LinuxHost(
            claude_linux.LinuxHostKind.LINUX, "x64", "6.8"
        )
        self.spec = claude_linux.SandboxSpec(
            host=self.host,
            toolchain=self.tools,
            claude=self.claude,
            launcher=self.launcher,
            workspace=self.workspace,
            helper_root=self.helper,
            helper_home=self.home,
            helper_tmp=self.tmp,
            config_dir=self.config,
            proxy_socket=self.proxy_path,
            runtime_libraries=(
                claude_linux.RuntimeMount(
                    self.library,
                    pathlib.PurePosixPath("/lib/libexample.so"),
                    library_identity,
                ),
            ),
        )

    def tearDown(self) -> None:
        self.socket_validation.stop()
        self.temporary.cleanup()

    def test_builds_synthetic_root_no_shell_review_command(self) -> None:
        review_arguments = _linux_review_arguments()
        sandbox_command = claude_linux.build_sandbox_command(
            self.spec,
            review_arguments,
            auth_env={"ANTHROPIC_API_KEY": "test-only"},
        )
        command = sandbox_command.argv

        for required in (
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-cgroup",
            "--remount-ro",
        ):
            self.assertIn(required, command)
        self.assertIn(
            ("--ro-bind", str(self.workspace.resolve()), "/workspace"),
            tuple(zip(command, command[1:], command[2:])),
        )
        self.assertIn(
            ("--bind", str(self.home.resolve()), "/home/reviewer"),
            tuple(zip(command, command[1:], command[2:])),
        )
        self.assertIn(
            ("--bind", str(self.config_root.resolve()), "/auth"),
            tuple(zip(command, command[1:], command[2:])),
        )
        self.assertNotIn("sh", {pathlib.Path(item).name for item in command})
        self.assertNotIn("/mnt", command)
        self.assertNotIn("/etc/claude-code", command)
        self.assertNotIn("test-only", command)
        self.assertEqual(sandbox_command.env, {"ANTHROPIC_API_KEY": "test-only"})
        self.assertNotIn("--clearenv", command)
        environment_triples = tuple(zip(command, command[1:], command[2:]))
        for key in (
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
            "CLAUDE_CODE_SAFE_MODE",
            "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB",
        ):
            self.assertIn(("--setenv", key, "1"), environment_triples)
        self.assertIn(
            ("--setenv", "CLAUDE_CONFIG_DIR", "/auth/config"),
            environment_triples,
        )
        workload = (
            "/opt/codex-review/bin/claude-linux-launcher",
            "--proxy",
            "/run/codex-review/proxy.sock",
            "--socat",
            "/opt/codex-review/bin/socat",
            "--",
            "/opt/codex-review/bin/claude",
            *review_arguments,
        )
        self.assertEqual(command[-len(workload) :], workload)
        settings = json.loads(
            review_arguments[review_arguments.index("--settings") + 1]
        )
        self.assertEqual(
            review_arguments[review_arguments.index("--permission-mode") + 1],
            "dontAsk",
        )
        self.assertEqual(
            review_arguments[review_arguments.index("--tools") + 1], "Read"
        )
        self.assertIn("Read(//auth/**)", settings["permissions"]["deny"])
        self.assertIn("Read(//proc/**)", settings["permissions"]["deny"])
        self.assertNotIn(
            "Grep", review_arguments[review_arguments.index("--tools") + 1]
        )
        self.assertIn(
            "Grep",
            review_arguments[review_arguments.index("--disallowedTools") + 1].split(
                ","
            ),
        )

    def test_rejects_config_without_dedicated_carrier_shape(self) -> None:
        direct_config = self.helper / "config"
        direct_config.mkdir(mode=0o700)
        wrong_leaf = self.config_root / "settings"
        wrong_leaf.mkdir(mode=0o700)

        for label, config_dir in (
            ("missing-carrier-root", direct_config),
            ("wrong-config-leaf", wrong_leaf),
        ):
            with (
                self.subTest(case=label),
                self.assertRaisesRegex(
                    claude_linux.LinuxRuntimeError,
                    "dedicated carrier root",
                ),
            ):
                claude_linux.build_sandbox_command(
                    dataclasses.replace(self.spec, config_dir=config_dir),
                    _linux_review_arguments(),
                )

    def test_rejects_auth_carrier_overlap_with_other_writable_roles(self) -> None:
        home_config = self.home / "config"
        tmp_config = self.tmp / "config"
        carrier_home = self.config_root / "nested-home"
        carrier_tmp = self.config_root / "nested-tmp"
        for directory in (
            home_config,
            tmp_config,
            carrier_home,
            carrier_tmp,
        ):
            directory.mkdir(mode=0o700)

        for label, spec in (
            (
                "config-under-home",
                dataclasses.replace(self.spec, config_dir=home_config),
            ),
            (
                "config-under-tmp",
                dataclasses.replace(self.spec, config_dir=tmp_config),
            ),
            (
                "home-under-carrier",
                dataclasses.replace(self.spec, helper_home=carrier_home),
            ),
            (
                "tmp-under-carrier",
                dataclasses.replace(self.spec, helper_tmp=carrier_tmp),
            ),
        ):
            with (
                self.subTest(case=label),
                self.assertRaisesRegex(
                    claude_linux.LinuxRuntimeError,
                    "authentication carrier must not overlap",
                ),
            ):
                claude_linux.build_sandbox_command(
                    spec,
                    _linux_review_arguments(),
                )

    def test_rejects_workspace_symlinks_to_authentication_carriers(self) -> None:
        link = self.workspace / "leak"
        for target in ("/auth/config/.credentials.json", "/proc/self/environ"):
            with self.subTest(target=target):
                link.symlink_to(target)
                try:
                    with self.assertRaisesRegex(
                        claude_linux.LinuxRuntimeUnsafe,
                        "symlink escapes.*workspace",
                    ):
                        claude_linux.build_sandbox_command(
                            self.spec,
                            _linux_review_arguments(),
                            auth_env={"ANTHROPIC_API_KEY": "test-only"},
                        )
                finally:
                    link.unlink()

    def test_accepts_workspace_symlink_that_resolves_inside_workspace(self) -> None:
        (self.workspace / "README-link.md").symlink_to("README.md")

        command = claude_linux.build_sandbox_command(
            self.spec,
            _linux_review_arguments(),
        )

        self.assertIn(str(self.workspace.resolve()), command.argv)

    def test_workspace_symlink_limit_does_not_count_intermediate_directories(
        self,
    ) -> None:
        current = self.workspace
        for index in range(8):
            current = current / f"level-{index}"
            current.mkdir()
        internal_target = pathlib.Path(*([".."] * 8)) / "README.md"
        (current / "README-link.md").symlink_to(internal_target)

        with mock.patch.object(claude_linux, "WORKSPACE_SYMLINK_LIMIT", 1):
            claude_linux.build_sandbox_command(
                self.spec,
                _linux_review_arguments(),
            )
            (self.workspace / "second-link.md").symlink_to("README.md")
            with self.assertRaisesRegex(
                claude_linux.LinuxRuntimeInspectionInconclusive,
                "symlink inspection limit",
            ):
                claude_linux.build_sandbox_command(
                    self.spec,
                    _linux_review_arguments(),
                )

    def test_mounts_private_ca_bundle_with_captured_path_identity(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            bundle = pathlib.Path(temporary) / "bundle.pem"
            bundle.write_bytes(b"test-only CA material\n")
            bundle.chmod(0o600)

            command = claude_linux.build_sandbox_command(
                dataclasses.replace(
                    self.spec,
                    ca_bundle=bundle,
                    node_extra_ca_certs_configured=True,
                ),
                _linux_review_arguments(),
            ).argv

        ca_mount = (
            "--ro-bind",
            str(bundle.resolve()),
            str(claude_linux.SANDBOX_CA_BUNDLE),
        )
        command_triples = tuple(zip(command, command[1:], command[2:]))
        self.assertIn(ca_mount, command_triples)
        self.assertEqual(command_triples.count(ca_mount), 1)
        environment_triples = command_triples
        self.assertIn(
            (
                "--setenv",
                "NODE_EXTRA_CA_CERTS",
                str(claude_linux.SANDBOX_CA_BUNDLE),
            ),
            environment_triples,
        )
        self.assertIn(
            (
                "--setenv",
                "SSL_CERT_FILE",
                str(claude_linux.SANDBOX_CA_BUNDLE),
            ),
            environment_triples,
        )

    def test_rejects_node_extra_ca_state_without_private_bundle(self) -> None:
        with self.assertRaisesRegex(
            claude_linux.LinuxRuntimeError,
            "requires a private CA bundle",
        ):
            claude_linux.build_sandbox_command(
                dataclasses.replace(
                    self.spec,
                    node_extra_ca_certs_configured=True,
                ),
                _linux_review_arguments(),
            )

    def test_rejects_non_boolean_node_extra_ca_state(self) -> None:
        with self.assertRaisesRegex(
            claude_linux.LinuxRuntimeError,
            "must be boolean",
        ):
            claude_linux.build_sandbox_command(
                dataclasses.replace(
                    self.spec,
                    node_extra_ca_certs_configured="yes",
                ),
                _linux_review_arguments(),
            )

    def test_rejects_ca_bundle_path_replacement_after_validation(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            bundle = root / "bundle.pem"
            replacement = root / "replacement.pem"
            bundle.write_bytes(b"original CA material\n")
            replacement.write_bytes(b"replacement material\n")
            bundle.chmod(0o600)
            replacement.chmod(0o600)
            original_mount_directories = claude_linux._mount_directories

            def replace_bundle(*args, **kwargs):
                os.replace(replacement, bundle)
                return original_mount_directories(*args, **kwargs)

            with (
                mock.patch.object(
                    claude_linux,
                    "_mount_directories",
                    side_effect=replace_bundle,
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxRuntimeInspectionInconclusive,
                    "changed after inspection",
                ),
            ):
                claude_linux.build_sandbox_command(
                    dataclasses.replace(self.spec, ca_bundle=bundle),
                    _linux_review_arguments(),
                )

    def test_rejects_ca_bundle_in_place_mutation_after_validation(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            bundle = pathlib.Path(temporary) / "bundle.pem"
            bundle.write_bytes(b"original CA material\n")
            bundle.chmod(0o600)
            original_mount_directories = claude_linux._mount_directories

            def mutate_bundle(*args, **kwargs):
                previous = bundle.stat()
                bundle.write_bytes(b"modified CA material\n")
                os.utime(
                    bundle,
                    ns=(previous.st_atime_ns, previous.st_mtime_ns + 1_000_000_000),
                )
                return original_mount_directories(*args, **kwargs)

            with (
                mock.patch.object(
                    claude_linux,
                    "_mount_directories",
                    side_effect=mutate_bundle,
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxRuntimeInspectionInconclusive,
                    "changed after inspection",
                ),
            ):
                claude_linux.build_sandbox_command(
                    dataclasses.replace(self.spec, ca_bundle=bundle),
                    _linux_review_arguments(),
                )

    def test_ca_symlink_retarget_does_not_change_captured_mount_source(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            root = pathlib.Path(temporary)
            targets = root / "targets"
            aliases = root / "aliases"
            targets.mkdir(mode=0o700)
            aliases.mkdir(mode=0o700)
            first = targets / "first.pem"
            second = targets / "second.pem"
            first.write_bytes(b"first CA material\n")
            second.write_bytes(b"second CA material\n")
            first.chmod(0o600)
            second.chmod(0o600)
            bundle = aliases / "bundle.pem"
            bundle.symlink_to(first)
            original_mount_directories = claude_linux._mount_directories

            def retarget_bundle(*args, **kwargs):
                bundle.unlink()
                bundle.symlink_to(second)
                return original_mount_directories(*args, **kwargs)

            with mock.patch.object(
                claude_linux,
                "_mount_directories",
                side_effect=retarget_bundle,
            ):
                command = claude_linux.build_sandbox_command(
                    dataclasses.replace(self.spec, ca_bundle=bundle),
                    _linux_review_arguments(),
                ).argv

        triples = tuple(zip(command, command[1:], command[2:]))
        self.assertIn(
            (
                "--ro-bind",
                str(first.resolve()),
                str(claude_linux.SANDBOX_CA_BUNDLE),
            ),
            triples,
        )
        self.assertNotIn(
            (
                "--ro-bind",
                str(second.resolve()),
                str(claude_linux.SANDBOX_CA_BUNDLE),
            ),
            triples,
        )

    def test_rejects_ca_bundle_below_writable_path_component(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            writable = pathlib.Path(temporary) / "writable"
            writable.mkdir()
            bundle = writable / "bundle.pem"
            bundle.write_bytes(b"test-only CA material\n")
            bundle.chmod(0o600)
            writable.chmod(0o777)

            with self.assertRaisesRegex(
                claude_linux.LinuxRuntimeUnsafe,
                "writable",
            ):
                claude_linux.build_sandbox_command(
                    dataclasses.replace(self.spec, ca_bundle=bundle),
                    _linux_review_arguments(),
                )

    def test_rejects_empty_ca_bundle(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=pathlib.Path(__file__).parent
        ) as temporary:
            bundle = pathlib.Path(temporary) / "bundle.pem"
            bundle.touch()
            bundle.chmod(0o600)

            with self.assertRaisesRegex(
                claude_linux.LinuxRuntimeError,
                "non-empty regular file",
            ):
                claude_linux.build_sandbox_command(
                    dataclasses.replace(self.spec, ca_bundle=bundle),
                    _linux_review_arguments(),
                )

    def test_mounts_available_system_ca_bundle(self) -> None:
        bundle = next(
            (
                path
                for path in (
                    pathlib.Path("/etc/ssl/certs/ca-certificates.crt"),
                    pathlib.Path("/etc/ssl/cert.pem"),
                    pathlib.Path("/etc/pki/tls/certs/ca-bundle.crt"),
                )
                if path.is_file()
            ),
            None,
        )
        if bundle is None:
            self.skipTest("a default system CA bundle is unavailable")

        command = claude_linux.build_sandbox_command(
            dataclasses.replace(self.spec, ca_bundle=bundle),
            _linux_review_arguments(),
        ).argv

        self.assertIn(
            (
                "--ro-bind",
                str(bundle.resolve()),
                str(claude_linux.SANDBOX_CA_BUNDLE),
            ),
            tuple(zip(command, command[1:], command[2:])),
        )
        self.assertNotIn(
            "NODE_EXTRA_CA_CERTS",
            command,
        )

    def test_bootstrap_probe_has_no_proxy_or_auxiliary_tools(self) -> None:
        library_root = pathlib.Path("/usr/lib")
        if not library_root.is_dir() or library_root.stat().st_uid != 0:
            self.skipTest("a root-owned /usr/lib is unavailable")
        command = claude_linux.build_probe_command(
            self.host,
            self.tools,
            self.claude,
            self.home,
            self.spec.runtime_libraries,
            ("--version",),
            library_roots=(library_root,),
        )

        self.assertIn("--unshare-net", command)
        self.assertIn(
            ("--ro-bind", str(self.home.resolve()), "/home/reviewer"),
            tuple(zip(command, command[1:], command[2:])),
        )
        self.assertNotIn("--proxy", command)
        self.assertNotIn("/opt/codex-review/bin/socat", command)
        self.assertNotIn("/opt/codex-review/bin/rg", command)
        self.assertIn(
            ("--ro-bind", str(library_root.resolve()), "/usr/lib"),
            tuple(zip(command, command[1:], command[2:])),
        )
        self.assertEqual(
            command[-3:],
            ("/opt/codex-review/bin/claude", "--safe-mode", "--version"),
        )

    def test_isolation_probe_uses_same_launcher_and_checks_fixed_paths(self) -> None:
        calls: list[tuple[str, ...]] = []

        def runner(argv, **_kwargs):
            calls.append(tuple(argv))
            return _capture(stdout=claude_linux.PROBE_SUCCESS)

        hidden_home = self.root / "host-home"
        hidden_home.mkdir()
        claude_linux.run_isolation_probe(
            self.spec,
            self.workspace / "README.md",
            host_home=hidden_home,
            runner=runner,
        )

        command = calls[0]
        probe_index = command.index("--probe")
        self.assertEqual(
            command[probe_index - 1], "/opt/codex-review/bin/claude-linux-launcher"
        )
        self.assertEqual(command[probe_index + 1], "/workspace/README.md")
        self.assertEqual(
            command[probe_index + 2 : probe_index + 5],
            ("/workspace", "/home/reviewer", "/tmp"),
        )
        self.assertEqual(command[probe_index + 5], str(hidden_home.resolve()))

    def test_descriptor_workspace_mount_is_shared_by_probe_and_review(self) -> None:
        descriptor = os.open(
            self.workspace,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

        def runner(argv, **kwargs):
            calls.append((tuple(argv), kwargs))
            return _capture(stdout=claude_linux.PROBE_SUCCESS)

        try:
            spec = dataclasses.replace(
                self.spec,
                workspace_descriptor=descriptor,
            )
            review_command = claude_linux.build_sandbox_command(
                spec,
                _linux_review_arguments(),
            )
            hidden_home = self.root / "host-home-descriptor"
            hidden_home.mkdir()
            claude_linux.run_isolation_probe(
                spec,
                self.workspace / "README.md",
                host_home=hidden_home,
                runner=runner,
            )
        finally:
            os.close(descriptor)

        expected_mount = ("--ro-bind-fd", str(descriptor), "/workspace")
        review_triples = tuple(
            zip(
                review_command.argv,
                review_command.argv[1:],
                review_command.argv[2:],
            )
        )
        self.assertIn(expected_mount, review_triples)
        self.assertNotIn(str(self.workspace.resolve()), review_command.argv)
        self.assertEqual(review_command.pass_fds, (descriptor,))
        probe_command, probe_kwargs = calls[0]
        self.assertIn(
            expected_mount,
            tuple(zip(probe_command, probe_command[1:], probe_command[2:])),
        )
        self.assertEqual(probe_kwargs["pass_fds"], (descriptor,))

    def test_rejects_unexpected_auth_environment(self) -> None:
        with self.assertRaisesRegex(claude_linux.LinuxRuntimeError, "unsupported"):
            claude_linux.build_sandbox_command(
                self.spec, ("--version",), auth_env={"PATH": "/untrusted"}
            )

    def test_local_login_command_clears_inherited_environment(self) -> None:
        command = claude_linux.build_sandbox_command(
            self.spec, _linux_review_arguments()
        )

        self.assertIn("--clearenv", command.argv)
        self.assertEqual(command.env, {})

    def test_rejects_incomplete_linux_file_tool_boundary(self) -> None:
        arguments = list(_linux_review_arguments())
        settings_index = arguments.index("--settings") + 1
        settings = json.loads(arguments[settings_index])
        settings["permissions"]["deny"].remove("Read(//proc/**)")
        arguments[settings_index] = json.dumps(settings, separators=(",", ":"))

        with self.assertRaisesRegex(
            claude_linux.LinuxRuntimeUnsafe,
            "omit synthetic-root file-tool denies",
        ):
            claude_linux.build_sandbox_command(self.spec, tuple(arguments))

    def test_rejects_cli_boundary_that_exposes_search_tools(self) -> None:
        arguments = list(_linux_review_arguments())
        tools_index = arguments.index("--tools") + 1
        arguments[tools_index] = "Read,Grep,Glob"

        with self.assertRaisesRegex(
            claude_linux.LinuxRuntimeUnsafe,
            "unexpected built-in tool set",
        ):
            claude_linux.build_sandbox_command(self.spec, tuple(arguments))

    def test_rejects_separate_mount_below_allowed_workspace(self) -> None:
        with self.assertRaisesRegex(
            claude_linux.LinuxRuntimeUnsafe,
            "separate mount below the allowed workspace",
        ):
            claude_linux._validate_linux_review_tool_boundary(
                _linux_review_arguments(),
                (
                    pathlib.PurePosixPath("/workspace"),
                    pathlib.PurePosixPath("/workspace/secret"),
                ),
            )


class ProxySocketValidationTest(unittest.TestCase):
    def test_accepts_short_private_tmp_socket_and_rejects_nonprivate_parent(
        self,
    ) -> None:
        host = claude_linux.LinuxHost(claude_linux.LinuxHostKind.LINUX, "x64", "6.8")
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            private_parent = root / "proxy-private"
            private_parent.mkdir(mode=0o700)
            private_path = private_parent / "p.sock"
            private_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                try:
                    private_socket.bind(str(private_path))
                except PermissionError as error:
                    self.skipTest(f"local sandbox blocks Unix socket creation: {error}")
                private_path.chmod(0o600)

                accepted = claude_linux._validate_private_socket(
                    private_path,
                    helper_root=helper.resolve(),
                    owner_uid=os.getuid(),
                    host=host,
                )

                self.assertEqual(accepted, private_path.resolve())
            finally:
                private_socket.close()
            real_parent = root / "proxy-real"
            real_parent.mkdir(mode=0o700)
            symlink_parent = root / "proxy-link"
            symlink_parent.symlink_to(real_parent, target_is_directory=True)
            real_path = real_parent / "p.sock"
            alias_path = symlink_parent / "p.sock"
            symlink_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                symlink_socket.bind(str(real_path))
                real_path.chmod(0o600)
                with self.assertRaisesRegex(
                    claude_linux.LinuxRuntimeError,
                    "parent path must not contain symlinks",
                ):
                    claude_linux._validate_private_socket(
                        alias_path,
                        helper_root=helper.resolve(),
                        owner_uid=os.getuid(),
                        host=host,
                    )
            finally:
                symlink_socket.close()
            nonprivate_parent = root / "proxy-shared"
            nonprivate_parent.mkdir(mode=0o755)
            nonprivate_path = nonprivate_parent / "p.sock"
            nonprivate_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                nonprivate_socket.bind(str(nonprivate_path))
                nonprivate_path.chmod(0o600)
                with self.assertRaisesRegex(claude_linux.LinuxRuntimeError, "0700"):
                    claude_linux._validate_private_socket(
                        nonprivate_path,
                        helper_root=helper.resolve(),
                        owner_uid=os.getuid(),
                        host=host,
                    )
            finally:
                nonprivate_socket.close()


class LauncherSignalCancellationTest(unittest.TestCase):
    def test_source_contract_guards_fork_publication_and_child_exec(self) -> None:
        source = claude_linux.LAUNCHER_SOURCE.read_text(encoding="utf-8")

        self.assertIn("sigprocmask(SIG_BLOCK", source)
        self.assertIn("pending_forwarded_signal()", source)
        self.assertIn("establish_child_process_group(child)", source)
        self.assertIn("prepare_child_signal_state(restore_mask)", source)
        self.assertIn("raise(SIGSTOP)", source)
        self.assertIn("release_child_process_group(workload)", source)
        self.assertLess(
            source.index("proxy_pid = proxy;"),
            source.index("signal restore after proxy launch"),
        )
        self.assertLess(
            source.index("workload_pid = workload;"),
            source.index("signal restore after workload launch"),
        )

    def test_signal_during_proxy_readiness_cannot_launch_workload(self) -> None:
        compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
        if compiler is None:
            self.skipTest("a C11 compiler is unavailable")
        listener_guard = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener_guard.bind(("127.0.0.1", 3128))
        except OSError as error:
            listener_guard.close()
            self.skipTest(f"launcher test proxy port is unavailable: {error}")
        listener_guard.close()

        with tempfile.TemporaryDirectory(prefix="claude-launcher-signal-") as temporary:
            root = pathlib.Path(temporary)
            launcher = root / "launcher"
            completed = subprocess.run(
                (
                    compiler,
                    "-std=c11",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-D_POSIX_C_SOURCE=200809L",
                    str(claude_linux.LAUNCHER_SOURCE),
                    "-o",
                    str(launcher),
                ),
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            proxy_started = root / "proxy-started"
            workload_started = root / "workload-started"
            fake_socat = root / "fake-socat"
            fake_socat.write_text(
                '#!/bin/sh\n: > "$FAKE_PROXY_STARTED"\nexec /bin/sleep 30\n',
                encoding="utf-8",
            )
            fake_socat.chmod(0o500)
            workload = root / "workload"
            workload.write_text(
                '#!/bin/sh\n: > "$FAKE_WORKLOAD_STARTED"\n',
                encoding="utf-8",
            )
            workload.chmod(0o500)
            environment = dict(os.environ)
            environment["FAKE_PROXY_STARTED"] = str(proxy_started)
            environment["FAKE_WORKLOAD_STARTED"] = str(workload_started)
            process = subprocess.Popen(
                (
                    str(launcher),
                    "--proxy",
                    str(root / "unused-proxy.sock"),
                    "--socat",
                    str(fake_socat),
                    "--",
                    str(workload),
                ),
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                deadline = time.monotonic() + 5.0
                while not proxy_started.exists() and time.monotonic() < deadline:
                    if process.poll() is not None:
                        break
                    time.sleep(0.01)
                self.assertTrue(proxy_started.exists(), "proxy child did not start")
                process.send_signal(signal.SIGTERM)
                _stdout, stderr = process.communicate(timeout=5.0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5.0)

            self.assertEqual(process.returncode, 128 + signal.SIGTERM, stderr.decode())
            self.assertFalse(workload_started.exists())


@unittest.skipUnless(
    sys.platform.startswith("linux")
    and os.environ.get("CODEX_REVIEW_RUN_LINUX_ISOLATION_INTEGRATION") == "1",
    "set CODEX_REVIEW_RUN_LINUX_ISOLATION_INTEGRATION=1 on Linux",
)
class LinuxIsolationIntegrationTest(unittest.TestCase):
    def test_real_synthetic_root_proxy_and_negative_isolation(self) -> None:
        host = claude_linux.detect_host()
        claude_linux.require_supported_host(host)
        toolchain = claude_linux.discover_native_toolchain(host)

        with tempfile.TemporaryDirectory(prefix="cc-li-", dir="/tmp") as temporary:
            root = pathlib.Path(temporary)
            root.chmod(0o700)
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            marker = workspace / "probe.txt"
            marker.write_text("workspace read marker\n", encoding="utf-8")
            original_workspace_entries = tuple(
                sorted(path.name for path in workspace.iterdir())
            )

            helper_root = root / "helper"
            helper_root.mkdir(mode=0o700)
            helper_home = helper_root / "home"
            helper_tmp = helper_root / "tmp"
            config_root = helper_root / "auth-carrier"
            config_dir = config_root / "config"
            launcher_dir = helper_root / "bin"
            for directory in (
                helper_home,
                helper_tmp,
                config_root,
                config_dir,
                launcher_dir,
            ):
                directory.mkdir(mode=0o700)
            launcher = claude_linux.compile_launcher(
                host,
                toolchain,
                launcher_dir / "claude-linux-launcher",
            )
            # The isolation probe never executes the Claude slot. A discovered,
            # root-owned native rg binary supplies a real ELF of the host ABI.
            claude_executable = toolchain.rg
            runtime_libraries = claude_linux.collect_runtime_libraries(
                host,
                (
                    claude_executable,
                    launcher,
                    toolchain.socat,
                    toolchain.rg,
                ),
            )
            hidden_host_path = root / "host-secret.txt"
            hidden_host_path.write_text("must stay outside sandbox\n", encoding="utf-8")
            proxy_dir = root / "proxy"
            proxy_dir.mkdir(mode=0o700)
            proxy_path = proxy_dir / "p.sock"

            with _ForbiddenConnectProxy(proxy_path) as proxy:
                spec = claude_linux.SandboxSpec(
                    host=host,
                    toolchain=toolchain,
                    claude=claude_executable,
                    launcher=launcher,
                    workspace=workspace,
                    helper_root=helper_root,
                    helper_home=helper_home,
                    helper_tmp=helper_tmp,
                    config_dir=config_dir,
                    proxy_socket=proxy_path,
                    runtime_libraries=runtime_libraries,
                )
                claude_linux.run_isolation_probe(
                    spec,
                    marker,
                    host_home=hidden_host_path,
                )

            self.assertEqual(proxy.errors, [])
            self.assertEqual(len(proxy.requests), 1)
            self.assertTrue(
                proxy.requests[0].startswith(
                    b"CONNECT example.invalid:443 HTTP/1.1\r\n"
                )
            )
            self.assertEqual(
                tuple(sorted(path.name for path in workspace.iterdir())),
                original_workspace_entries,
            )
            self.assertEqual(tuple(helper_home.iterdir()), ())
            self.assertEqual(tuple(helper_tmp.iterdir()), ())


if __name__ == "__main__":
    unittest.main()
