from __future__ import annotations

import contextlib
import dataclasses
import dis
import errno
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
import traceback
import unittest
from collections.abc import Callable, Iterator
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
    # refresh-a, refresh-b (pool joey-private-v3).
    SYNTH_ACCESS_EXPIRED = "codex_synth_v1_access_expired"
    SYNTH_ACCESS_A = "codex_synth_v1_access_a"
    SYNTH_ACCESS_B = "codex_synth_v1_access_b"
    SYNTH_REFRESH_A = "codex_synth_v1_refresh_a"
    SYNTH_REFRESH_B = "codex_synth_v1_refresh_b"

    @staticmethod
    def _explicit_cause_nodes(
        error: BaseException,
    ) -> tuple[BaseException, ...]:
        nodes: list[BaseException] = []
        seen: set[int] = set()
        current: BaseException | None = error
        while current is not None and len(nodes) < 32:
            identity = id(current)
            if identity in seen:
                break
            seen.add(identity)
            nodes.append(current)
            current = current.__cause__
        return tuple(nodes)

    @classmethod
    def _visible_explicit_cause_text(cls, error: BaseException) -> str:
        visible: list[str] = []
        for node in cls._explicit_cause_nodes(error):
            visible.append(str(node))
            visible.extend(getattr(node, "__notes__", ()))
        return "\n".join(visible)

    class _CoordinatorLeaseFixture:
        def __init__(
            self,
            *,
            release_callback: Callable[[], None] | None = None,
            assert_held_side_effect: object = None,
            abandonment_diagnostic: (
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive | None
            ) = None,
        ) -> None:
            self._state_lock = threading.Lock()
            self._terminal = False
            self._heartbeat_stop = threading.Event()
            self._deletion_prohibited = False
            self._release_callback = release_callback
            self._abandonment_diagnostic = abandonment_diagnostic
            self.assert_held = mock.Mock(side_effect=assert_held_side_effect)
            self.release = mock.Mock(side_effect=self._record_release)
            self.abandon = mock.Mock(side_effect=self._record_abandon)

        def _record_release(self) -> None:
            if self._release_callback is not None:
                self._release_callback()
            with self._state_lock:
                self._terminal = True

        def _record_abandon(
            self,
            _reason: str,
        ) -> claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive | None:
            with self._state_lock:
                self._terminal = True
            return self._abandonment_diagnostic

        def _release(self, *, skip_abandoned: bool) -> None:
            if skip_abandoned:
                raise AssertionError(
                    "coordinator fixture requires explicit destructive release"
                )
            self.release()

        def retention_snapshot(
            self,
        ) -> claude_refresh_lock.ClaudeRefreshLockRetentionSnapshot:
            with self._state_lock:
                terminal = self._terminal
            return claude_refresh_lock.ClaudeRefreshLockRetentionSnapshot(
                terminal=terminal,
                verified_closed=(terminal and self._abandonment_diagnostic is None),
                diagnostic=(self._abandonment_diagnostic if terminal else None),
            )

    def _interrupt_acquire_assignment(
        self,
        function: object,
        *,
        local_name: str,
        armed: list[bool],
        error: BaseException,
    ) -> mock._patch:
        code = function.__code__
        instructions = {
            instruction.offset: instruction
            for instruction in dis.get_instructions(function)
        }
        previous_trace = sys.gettrace()

        def trace(frame: object, event: str, _argument: object) -> object:
            if frame.f_code is code:
                frame.f_trace_opcodes = True
                instruction = instructions.get(frame.f_lasti)
                if (
                    event == "opcode"
                    and armed[0]
                    and instruction is not None
                    and instruction.opname in {"STORE_FAST", "STORE_DEREF"}
                    and instruction.argval == local_name
                ):
                    armed[0] = False
                    raise error
            return trace

        class TracePatch:
            def __enter__(self) -> None:
                sys.settrace(trace)

            def __exit__(
                self,
                _error_type: object,
                _error: object,
                _traceback: object,
            ) -> None:
                sys.settrace(previous_trace)

        return TracePatch()

    def _interrupt_attribute_assignment(
        self,
        function: object,
        *,
        target: object,
        attribute_name: str,
        error: BaseException,
    ) -> mock._patch:
        code = function.__code__
        offsets = {
            instruction.offset
            for instruction in dis.get_instructions(function)
            if instruction.opname == "STORE_ATTR"
            and instruction.argval == attribute_name
        }
        self.assertTrue(offsets)
        previous_trace = sys.gettrace()
        armed = [True]

        def trace(frame: object, event: str, _argument: object) -> object:
            if frame.f_code is code:
                frame.f_trace_opcodes = True
                if (
                    event == "opcode"
                    and armed[0]
                    and frame.f_lasti in offsets
                    and frame.f_locals.get("self") is target
                ):
                    armed[0] = False
                    raise error
            return trace

        class TracePatch:
            def __enter__(self) -> None:
                sys.settrace(trace)

            def __exit__(
                self,
                _error_type: object,
                _error: object,
                _traceback: object,
            ) -> None:
                sys.settrace(previous_trace)

        return TracePatch()

    def _interrupt_release_call_entry(
        self,
        *,
        armed: list[bool],
        error: BaseException,
        target_lease: list[claude_refresh_lock.ClaudeRefreshLockLease],
    ) -> mock._patch:
        function = claude_linux._release_owned_claude_refresh_lock
        code = function.__code__
        instructions = list(dis.get_instructions(function))
        release_call_offsets: set[int] = set()
        for index, instruction in enumerate(instructions):
            if instruction.argval != "release" or instruction.opname not in {
                "LOAD_ATTR",
                "LOAD_METHOD",
            }:
                continue
            for candidate in instructions[index + 1 :]:
                if candidate.opname.startswith("CALL"):
                    release_call_offsets.add(candidate.offset)
                    break
        self.assertTrue(release_call_offsets)
        release_call_offsets = {min(release_call_offsets)}
        previous_trace = sys.gettrace()

        def trace(frame: object, event: str, _argument: object) -> object:
            if frame.f_code is code:
                frame.f_trace_opcodes = True
                if (
                    event == "opcode"
                    and armed[0]
                    and frame.f_lasti in release_call_offsets
                    and target_lease
                    and frame.f_locals.get("cleanup_lease") is target_lease[0]
                ):
                    armed[0] = False
                    raise error
            return trace

        class TracePatch:
            def __enter__(self) -> None:
                sys.settrace(trace)

            def __exit__(
                self,
                _error_type: object,
                _error: object,
                _traceback: object,
            ) -> None:
                sys.settrace(previous_trace)

        return TracePatch()

    def _interrupt_cleanup_call_boundaries(
        self,
        function: object,
        *,
        target_lease: list[claude_refresh_lock.ClaudeRefreshLockLease],
        injections: list[tuple[str, str, list[BaseException]]],
        include_new_threads: bool = False,
    ) -> mock._patch:
        code = function.__code__
        instructions = list(dis.get_instructions(function))
        offsets_by_boundary: dict[tuple[str, str], set[int]] = {}
        for method_name, window, _errors in injections:
            boundary = (method_name, window)
            if boundary in offsets_by_boundary:
                continue
            offsets: set[int] = set()
            for index, instruction in enumerate(instructions):
                if instruction.argval != method_name or instruction.opname not in {
                    "LOAD_ATTR",
                    "LOAD_METHOD",
                }:
                    continue
                call_index: int | None = None
                for candidate_index in range(index + 1, len(instructions)):
                    if instructions[candidate_index].opname.startswith("CALL"):
                        call_index = candidate_index
                        break
                assert call_index is not None
                target_index = call_index if window == "entry" else call_index + 1
                self.assertLess(target_index, len(instructions))
                offsets.add(instructions[target_index].offset)
            self.assertTrue(offsets, boundary)
            offsets_by_boundary[boundary] = offsets
        remaining = [list(errors) for _name, _window, errors in injections]
        previous_trace = sys.gettrace()
        previous_thread_trace = threading.gettrace()

        def trace(frame: object, event: str, _argument: object) -> object:
            if frame.f_code is code:
                frame.f_trace_opcodes = True
                if event != "opcode" or not target_lease:
                    return trace
                cleanup_lease = next(
                    (
                        frame.f_locals.get(local_name)
                        for local_name in (
                            "cleanup_lease",
                            "cleanup_host_refresh_lock",
                            "lease",
                        )
                        if frame.f_locals.get(local_name) is target_lease[0]
                    ),
                    None,
                )
                if cleanup_lease is None:
                    return trace
                for index, (method_name, window, _errors) in enumerate(injections):
                    if (
                        remaining[index]
                        and frame.f_lasti in offsets_by_boundary[(method_name, window)]
                    ):
                        raise remaining[index].pop(0)
            return trace

        class TracePatch:
            def __enter__(self) -> None:
                if include_new_threads:
                    threading.settrace(trace)
                sys.settrace(trace)

            def __exit__(
                self,
                _error_type: object,
                _error: object,
                _traceback: object,
            ) -> None:
                sys.settrace(previous_trace)
                if include_new_threads:
                    threading.settrace(previous_thread_trace)

        return TracePatch()

    def _interrupt_function_call_boundary(
        self,
        function: object,
        *,
        callee_name: str,
        window: str,
        target_lease: list[claude_refresh_lock.ClaudeRefreshLockLease],
        error: BaseException,
        include_new_threads: bool = False,
    ) -> mock._patch:
        code = function.__code__
        instructions = list(dis.get_instructions(function))
        boundary_offsets: set[int] = set()
        for index, instruction in enumerate(instructions):
            if instruction.argval != callee_name:
                continue
            call_index: int | None = None
            for candidate_index in range(index + 1, len(instructions)):
                if instructions[candidate_index].opname.startswith("CALL"):
                    call_index = candidate_index
                    break
            assert call_index is not None
            target_index = call_index if window == "entry" else call_index + 1
            self.assertLess(target_index, len(instructions))
            boundary_offsets.add(instructions[target_index].offset)
        self.assertTrue(boundary_offsets)
        previous_trace = sys.gettrace()
        previous_thread_trace = threading.gettrace()
        armed = [True]

        def trace(frame: object, event: str, _argument: object) -> object:
            if frame.f_code is code:
                frame.f_trace_opcodes = True
                if (
                    event == "opcode"
                    and armed[0]
                    and frame.f_lasti in boundary_offsets
                    and target_lease
                    and any(
                        frame.f_locals.get(local_name) is target_lease[0]
                        for local_name in (
                            "cleanup_lease",
                            "cleanup_host_refresh_lock",
                            "lease",
                            "refresh_lock",
                            "stateful_lease",
                            "stateful_host_refresh_lock",
                        )
                    )
                ):
                    armed[0] = False
                    raise error
            return trace

        class TracePatch:
            def __enter__(self) -> None:
                if include_new_threads:
                    threading.settrace(trace)
                sys.settrace(trace)

            def __exit__(
                self,
                _error_type: object,
                _error: object,
                _traceback: object,
            ) -> None:
                sys.settrace(previous_trace)
                if include_new_threads:
                    threading.settrace(previous_thread_trace)

        return TracePatch()

    def _dispose_refresh_lock_fixture(
        self,
        lease: claude_refresh_lock.ClaudeRefreshLockLease,
    ) -> None:
        lease._heartbeat_stop.set()
        heartbeat = lease._heartbeat_thread
        if heartbeat is not None:
            heartbeat.join(timeout=2.0)
        if not lease.released and not lease._deletion_prohibited:
            lease._release(skip_abandoned=False)
            return
        descriptors = {
            *(lock.descriptor for lock in lease._locks),
            lease._legacy_parent_anchor.descriptor,
            lease._config_anchor.descriptor,
        }
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass

    @contextlib.contextmanager
    def _host_cleanup_coordinator_fixture(
        self,
        *,
        with_lease: bool,
        allow_source_residue: bool = False,
    ) -> Iterator[
        tuple[
            pathlib.Path,
            pathlib.Path,
            claude_linux._CredentialDirectoryAnchor,
            claude_linux._HostRefreshLockCleanupCoordinator,
            claude_refresh_lock.ClaudeRefreshLockLease | None,
        ]
    ]:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(time.time() - 60) * 1000,
            )
            source_anchor = claude_linux._open_credential_directory_anchor(
                source,
                owner_uid=os.getuid(),
            )
            source_descriptors = source_anchor._descriptors
            coordinator = claude_linux._HostRefreshLockCleanupCoordinator(source_anchor)
            lease: claude_refresh_lock.ClaudeRefreshLockLease | None = None
            if with_lease:
                lease = claude_linux.acquire_claude_refresh_lock(
                    source.parent,
                    protocol=self.PROTOCOL,
                    owner=coordinator.owner,
                    timeout_seconds=0,
                    config_dir_fd=source_anchor.descriptor,
                    legacy_parent_dir_fd=(source_anchor.legacy_parent_descriptor),
                    require_explicit_context_release=True,
                )
                coordinator.owner.transfer(lease)
            try:
                yield root, source, source_anchor, coordinator, lease
            finally:
                coordinator._terminal.set()
                if coordinator._thread.ident is not None:
                    coordinator._thread.join(timeout=1.0)
                if lease is not None:
                    self._dispose_refresh_lock_fixture(lease)
                if (
                    allow_source_residue
                    and source_anchor.disposition
                    is claude_linux._CredentialDirectoryAnchorDisposition.DESCRIPTOR_RESIDUE
                ):
                    for descriptor in source_descriptors:
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass
                    with source_anchor._state_lock:
                        source_anchor._descriptor_residue_latched = False
                        source_anchor._disposition = (
                            claude_linux._CredentialDirectoryAnchorDisposition.CLOSED
                        )
                        source_anchor._descriptor_residue_diagnostic = None
                        source_anchor._descriptors = ()
                else:
                    source_anchor.close_if_owned()

    def _assert_refresh_lock_descriptors_closed(
        self,
        lease: claude_refresh_lock.ClaudeRefreshLockLease,
    ) -> None:
        descriptors = {
            *(lock.descriptor for lock in lease._locks),
            lease._legacy_parent_anchor.descriptor,
            lease._config_anchor.descriptor,
        }
        for descriptor in descriptors:
            with self.assertRaises(OSError) as raised:
                os.fstat(descriptor)
            self.assertEqual(raised.exception.errno, errno.EBADF)

    def _assert_assignment_interrupt_released_lock(
        self,
        lease: claude_refresh_lock.ClaudeRefreshLockLease,
    ) -> None:
        heartbeat = lease._heartbeat_thread
        self.assertIsNotNone(heartbeat)
        assert heartbeat is not None
        self.assertFalse(
            heartbeat.is_alive(),
            "caller assignment interruption orphaned a renewing heartbeat",
        )
        self.assertTrue(lease.released)
        self.assertTrue(all(not path.exists() for path in lease.paths))

    def _assert_assignment_interrupt_retained_lock(
        self,
        lease: claude_refresh_lock.ClaudeRefreshLockLease,
    ) -> None:
        heartbeat = lease._heartbeat_thread
        self.assertIsNotNone(heartbeat)
        assert heartbeat is not None
        self.assertFalse(
            heartbeat.is_alive(),
            "caller assignment interruption orphaned a renewing heartbeat",
        )
        snapshot = lease.retention_snapshot()
        self.assertTrue(snapshot.terminal)
        self.assertTrue(snapshot.verified_closed)
        self.assertFalse(lease.released)
        self.assertTrue(lease._deletion_prohibited)
        self.assertTrue(all(path.is_dir() for path in lease.paths))
        self._assert_refresh_lock_descriptors_closed(lease)
        self.assertIsNotNone(snapshot.diagnostic)

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
        access_token: str | None = None,
        refresh_token: str = SYNTH_REFRESH_A,
    ) -> pathlib.Path:
        if access_token is None:
            # Boundary tests pass an explicit catalog fixture so scheduling
            # delay cannot change the logical token state.
            access_token = (
                self.SYNTH_ACCESS_EXPIRED
                if expires_at_ms <= time.time() * 1000
                else self.SYNTH_ACCESS_A
            )
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

    def test_default_access_fixture_tracks_expiry_state(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            active = self._credential(
                root / "active.json",
                expires_at_ms=(now + 7200) * 1000,
            )
            expired = self._credential(
                root / "expired.json",
                expires_at_ms=(now - 60) * 1000,
            )

            active_payload = json.loads(active.read_text(encoding="utf-8"))
            expired_payload = json.loads(expired.read_text(encoding="utf-8"))
            self.assertEqual(
                active_payload["claudeAiOauth"]["accessToken"],
                self.SYNTH_ACCESS_A,
            )
            self.assertEqual(
                expired_payload["claudeAiOauth"]["accessToken"],
                self.SYNTH_ACCESS_EXPIRED,
            )

    @staticmethod
    def _publish_test_signal_mask(
        *,
        signal_mask_owner: object | None = None,
    ) -> set[signal.Signals]:
        previous_mask = signal.pthread_sigmask(
            signal.SIG_BLOCK,
            claude_linux.forwarded_signals(),
        )
        assert signal_mask_owner is not None
        signal_mask_owner.publish(previous_mask)
        return previous_mask

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

    def test_credential_ancestor_retarget_during_host_lock_wait_blocks_read(
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
            lock_wait_entered = threading.Event()
            allow_lock_acquisition = threading.Event()
            credential_exposed = threading.Event()
            thread_errors: list[BaseException] = []
            host_leases: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
            real_acquire = claude_linux.acquire_claude_refresh_lock

            def acquire_refresh_lock(
                config_path: os.PathLike[str] | str,
                **kwargs: object,
            ) -> claude_refresh_lock.ClaudeRefreshLockLease:
                self.assertEqual(pathlib.Path(config_path), source.parent)
                lock_wait_entered.set()
                if not allow_lock_acquisition.wait(timeout=3.0):
                    raise TimeoutError("host lock wait fixture timed out")
                lease = real_acquire(config_path, **kwargs)
                host_leases.append(lease)
                return lease

            def stage_credential() -> None:
                try:
                    with claude_linux.stage_claude_credentials(
                        source,
                        helper,
                        now=now,
                        refresh_lock_protocol=self.PROTOCOL,
                    ):
                        credential_exposed.set()
                except BaseException as error:
                    thread_errors.append(error)

            staging_thread = threading.Thread(
                target=stage_credential,
                name="retarget-during-host-lock-wait",
                daemon=True,
            )
            with (
                mock.patch.object(
                    claude_linux,
                    "block_forwarded_signals",
                    side_effect=self._publish_test_signal_mask,
                ),
                mock.patch.object(
                    claude_linux,
                    "restore_signal_mask",
                ),
                mock.patch.object(
                    claude_linux,
                    "acquire_claude_refresh_lock",
                    side_effect=acquire_refresh_lock,
                ),
                mock.patch.object(
                    claude_linux,
                    "_read_valid_credential",
                    wraps=claude_linux._read_valid_credential,
                ) as read_credential,
            ):
                try:
                    staging_thread.start()
                    self.assertTrue(lock_wait_entered.wait(timeout=3.0))
                    home.rename(retained_home)
                    home.symlink_to(replacement_home, target_is_directory=True)
                    allow_lock_acquisition.set()
                    staging_thread.join(timeout=3.0)
                finally:
                    allow_lock_acquisition.set()
                    staging_thread.join(timeout=3.0)

            self.assertFalse(staging_thread.is_alive())
            self.assertFalse(credential_exposed.is_set())
            read_credential.assert_not_called()
            self.assertEqual(len(thread_errors), 1)
            self.assertIsInstance(
                thread_errors[0],
                claude_linux.LinuxCredentialInspectionInconclusive,
            )
            self.assertIn("ancestor changed", str(thread_errors[0]))
            self.assertEqual(len(host_leases), 1)
            self.assertTrue(host_leases[0].released)
            self.assertTrue(all(not path.exists() for path in host_leases[0].paths))
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
                        self.assertIs(
                            anchor.disposition,
                            claude_linux._CredentialDirectoryAnchorDisposition.OPEN,
                        )
                        if cleanup_first:
                            watcher._close_source_anchor_after_worker()
                            self.assertIs(
                                anchor.disposition,
                                claude_linux._CredentialDirectoryAnchorDisposition.OPEN,
                            )
                            watcher.retain_source_anchor_after_timeout()
                        else:
                            watcher.retain_source_anchor_after_timeout()
                            self.assertIs(
                                anchor.disposition,
                                claude_linux._CredentialDirectoryAnchorDisposition.TRANSFERRED,
                            )
                            self.assertIsInstance(anchor.descriptor, int)
                            watcher._close_source_anchor_after_worker()
                        self.assertIs(
                            anchor.disposition,
                            claude_linux._CredentialDirectoryAnchorDisposition.CLOSED,
                        )
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

    def test_watcher_cleanup_reached_retains_unknown_close_as_residue(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            config_dir = root / "config"
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
            target_descriptor = anchor._descriptors[-1]
            target_close_calls = 0
            real_close = claude_linux.os.close

            def close_then_report_unknown(descriptor: int) -> None:
                nonlocal target_close_calls
                real_close(descriptor)
                if descriptor == target_descriptor:
                    target_close_calls += 1
                    raise OSError("injected source-anchor close outcome unknown")

            try:
                watcher._close_source_anchor_after_worker()
                with (
                    mock.patch.object(
                        claude_linux.os,
                        "close",
                        side_effect=close_then_report_unknown,
                    ),
                    self.assertRaises(
                        claude_linux.LinuxCredentialInspectionInconclusive
                    ) as first,
                ):
                    watcher.retain_source_anchor_after_timeout()

                self.assertIs(
                    anchor.disposition,
                    claude_linux._CredentialDirectoryAnchorDisposition.DESCRIPTOR_RESIDUE,
                )
                self.assertIs(anchor.descriptor_residue_diagnostic, first.exception)
                self.assertTrue(
                    getattr(
                        first.exception,
                        "_codex_claude_refresh_lock_descriptor_bound",
                        False,
                    )
                )
                self.assertFalse(
                    hasattr(first.exception, "_codex_claude_refresh_lock_paths")
                )
                with self.assertRaises(
                    claude_linux.LinuxCredentialInspectionInconclusive
                ) as repeated:
                    watcher.retain_source_anchor_after_timeout()
                self.assertIs(repeated.exception, first.exception)
                self.assertEqual(target_close_calls, 1)
            finally:
                watcher.scrub()
                try:
                    if anchor.detached_to_watcher:
                        anchor.close_if_detached()
                    else:
                        anchor.close_if_owned()
                except claude_linux.LinuxCredentialInspectionInconclusive:
                    pass

    def test_source_anchor_publishes_residue_before_forgetting_descriptors(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            config_dir = root / "config"
            config_dir.mkdir(mode=0o700)
            source = self._credential(
                config_dir / ".credentials.json",
                expires_at_ms=(now + 7200) * 1000,
            )
            anchor = claude_linux._open_credential_directory_anchor(
                source,
                owner_uid=os.getuid(),
            )
            descriptors = anchor._descriptors
            control_flow = KeyboardInterrupt(
                "injected source-anchor descriptor-forget interruption"
            )
            real_close = claude_linux.os.close
            anchor.detach_to_watcher()
            try:
                with (
                    mock.patch.object(
                        claude_linux.os,
                        "close",
                        wraps=real_close,
                    ) as close_descriptor,
                    self._interrupt_attribute_assignment(
                        claude_linux._CredentialDirectoryAnchor._close_once,
                        target=anchor,
                        attribute_name="_descriptors",
                        error=control_flow,
                    ),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    anchor.close_if_detached()

                self.assertIs(raised.exception, control_flow)
                self.assertTrue(
                    getattr(
                        raised.exception,
                        "_codex_claude_refresh_lock_descriptor_bound",
                        False,
                    )
                )
                self.assertFalse(
                    hasattr(
                        raised.exception,
                        "_codex_claude_refresh_lock_paths",
                    )
                )
                self.assertIs(
                    anchor.disposition,
                    claude_linux._CredentialDirectoryAnchorDisposition.DESCRIPTOR_RESIDUE,
                )
                diagnostic = anchor.descriptor_residue_diagnostic
                self.assertIsNotNone(diagnostic)
                assert diagnostic is not None
                self.assertTrue(
                    getattr(
                        diagnostic,
                        "_codex_claude_refresh_lock_descriptor_bound",
                        False,
                    )
                )
                with self.assertRaises(
                    claude_linux.LinuxCredentialInspectionInconclusive
                ) as descriptor_read:
                    _ = anchor.descriptor
                self.assertIs(descriptor_read.exception, diagnostic)
                with self.assertRaises(
                    claude_linux.LinuxCredentialInspectionInconclusive
                ) as repeated:
                    anchor.close_if_detached()
                self.assertIs(repeated.exception, diagnostic)
                close_descriptor.assert_not_called()
            finally:
                for descriptor in descriptors:
                    try:
                        real_close(descriptor)
                    except OSError:
                        pass

    def test_source_anchor_residue_settlement_does_not_revive_closed_anchor(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now + 7200) * 1000,
            )
            anchor = claude_linux._open_credential_directory_anchor(
                source,
                owner_uid=os.getuid(),
            )
            anchor.close_if_owned()
            diagnostic = claude_linux.LinuxCredentialInspectionInconclusive(
                "injected late source-anchor residue settlement"
            )

            self.assertIsNone(anchor.settle_descriptor_bound_residue(diagnostic))
            self.assertIs(
                anchor.disposition,
                claude_linux._CredentialDirectoryAnchorDisposition.CLOSED,
            )
            self.assertIsNone(anchor.descriptor_residue_diagnostic)
            self.assertFalse(anchor._descriptor_residue_latched)
            anchor.close_if_owned()
            with self.assertRaisesRegex(
                claude_linux.LinuxCredentialInspectionInconclusive,
                "anchor is closed",
            ):
                _ = anchor.descriptor

    def test_source_anchor_residue_fallback_is_stable_across_publication_race(
        self,
    ) -> None:
        class PausingStateLock:
            def __init__(self) -> None:
                self._lock = threading.Lock()
                self.settlement_thread_id: int | None = None
                self.settlement_entered = threading.Event()
                self.allow_settlement = threading.Event()
                self._pause_once = True

            def __enter__(self) -> None:
                if (
                    self._pause_once
                    and threading.get_ident() == self.settlement_thread_id
                ):
                    self._pause_once = False
                    self.settlement_entered.set()
                    self.allow_settlement.wait(timeout=1.0)
                self._lock.acquire()

            def __exit__(
                self,
                _error_type: object,
                _error: object,
                _traceback: object,
            ) -> None:
                self._lock.release()

        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now + 7200) * 1000,
            )
            anchor = claude_linux._open_credential_directory_anchor(
                source,
                owner_uid=os.getuid(),
            )
            descriptors = anchor._descriptors
            pausing_lock = PausingStateLock()
            anchor._state_lock = pausing_lock  # type: ignore[assignment]
            requested = claude_linux.LinuxCredentialInspectionInconclusive(
                "injected contextual residue diagnostic"
            )
            results: list[
                claude_linux.LinuxCredentialInspectionInconclusive | None
            ] = []
            failures: list[BaseException] = []

            def settle_residue() -> None:
                pausing_lock.settlement_thread_id = threading.get_ident()
                try:
                    results.append(anchor.settle_descriptor_bound_residue(requested))
                except BaseException as error:
                    failures.append(error)

            settlement = threading.Thread(target=settle_residue, daemon=True)
            try:
                settlement.start()
                self.assertTrue(pausing_lock.settlement_entered.wait(timeout=0.5))
                observed = anchor.descriptor_residue_diagnostic
                self.assertIs(observed, anchor._descriptor_residue_fallback)
                pausing_lock.allow_settlement.set()
                settlement.join(timeout=1.0)

                self.assertFalse(settlement.is_alive())
                self.assertEqual(failures, [])
                self.assertEqual(results, [observed])
                self.assertIs(anchor.descriptor_residue_diagnostic, observed)
                with self.assertRaises(
                    claude_linux.LinuxCredentialInspectionInconclusive
                ) as descriptor_read:
                    _ = anchor.descriptor
                self.assertIs(descriptor_read.exception, observed)
            finally:
                pausing_lock.allow_settlement.set()
                settlement.join(timeout=1.0)
                for descriptor in descriptors:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                with anchor._state_lock:
                    anchor._descriptor_residue_latched = False
                    anchor._disposition = (
                        claude_linux._CredentialDirectoryAnchorDisposition.CLOSED
                    )
                    anchor._descriptor_residue_diagnostic = None
                    anchor._descriptors = ()

    def test_default_accepts_one_second_remaining(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now + 1) * 1000,
                access_token=self.SYNTH_ACCESS_A,
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
                access_token=self.SYNTH_ACCESS_A,
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
                access_token=self.SYNTH_ACCESS_EXPIRED,
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
                access_token=self.SYNTH_ACCESS_A,
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
            real_acquire = claude_linux.acquire_claude_refresh_lock

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

            with (
                mock.patch.object(
                    claude_linux,
                    "_writeback_refreshed_credential_impl",
                    side_effect=observe_writeback,
                ),
                mock.patch.object(
                    claude_linux,
                    "acquire_claude_refresh_lock",
                    wraps=real_acquire,
                ) as acquire_refresh_lock,
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

            self.assertEqual(
                sum(
                    pathlib.Path(call.args[0]) == source.parent
                    for call in acquire_refresh_lock.call_args_list
                ),
                1,
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

    def test_unknown_writer_start_retains_private_recovery_carrier(
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
                    writer_started=lambda: True,
                    writer_quiescent=lambda: False,
                ) as staged:
                    pass

            assert staged is not None
            self._assert_retained_recovery_carrier(
                error=raised.exception,
                staged=staged,
                helper=helper,
                expected_refresh_token=self.SYNTH_REFRESH_A,
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
                    "_read_valid_credential",
                    wraps=claude_linux._read_valid_credential,
                ) as read_credential,
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialStaleRefreshLock,
                    "stale Claude refresh lock",
                ),
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                    writer_quiescent=lambda: True,
                ):
                    self.fail("stale host refresh lock must block staging")

            self.assertTrue(host_lock.is_dir())
            read_credential.assert_not_called()
            self.assertEqual(list(helper.iterdir()), [])
            host = json.loads(source.read_text(encoding="utf-8"))
            self.assertEqual(
                host["claudeAiOauth"]["refreshToken"],
                self.SYNTH_REFRESH_A,
            )

    def test_host_refresh_lock_contention_blocks_source_read(self) -> None:
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
                    "acquire_claude_refresh_lock",
                    side_effect=claude_linux.ClaudeRefreshLockTimeout(
                        "fixture host refresh lock contention"
                    ),
                ) as acquire_refresh_lock,
                mock.patch.object(
                    claude_linux,
                    "_read_valid_credential",
                    wraps=claude_linux._read_valid_credential,
                ) as read_credential,
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialInspectionInconclusive,
                    "cannot coordinate Claude credential refresh transaction",
                ),
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ):
                    self.fail("contended host refresh lock must block staging")

            acquire_refresh_lock.assert_called_once_with(
                source.parent,
                protocol=self.PROTOCOL,
                owner=mock.ANY,
                config_dir_fd=mock.ANY,
                legacy_parent_dir_fd=mock.ANY,
                require_explicit_context_release=True,
            )
            read_credential.assert_not_called()
            self.assertEqual(list(helper.iterdir()), [])

    def test_staged_read_assignment_interrupt_releases_owner_lease(
        self,
    ) -> None:
        captured: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
        armed = [False]
        interruption = KeyboardInterrupt(
            "injected staged-read refresh-lock assignment interruption"
        )
        real_acquire = claude_linux.acquire_claude_refresh_lock

        def acquire_and_arm(
            *args: object,
            **kwargs: object,
        ) -> claude_refresh_lock.ClaudeRefreshLockLease:
            lease = real_acquire(*args, **kwargs)
            captured.append(lease)
            armed[0] = True
            return lease

        with tempfile.TemporaryDirectory() as temporary:
            carrier_root = pathlib.Path(temporary) / "carrier"
            carrier_root.mkdir(mode=0o700)
            config_dir = carrier_root / "config"
            config_dir.mkdir(mode=0o700)
            credential_path = self._credential(
                config_dir / ".credentials.json",
                expires_at_ms=(time.time() + 7200) * 1000,
            )
            staged = claude_linux.StagedCredential(
                carrier_root,
                config_dir,
                credential_path,
                0.0,
            )
            try:
                with (
                    mock.patch.object(
                        claude_linux,
                        "acquire_claude_refresh_lock",
                        side_effect=acquire_and_arm,
                    ),
                    self._interrupt_acquire_assignment(
                        claude_linux._read_staged_credential_under_lock,
                        local_name="refresh_lock",
                        armed=armed,
                        error=interruption,
                    ),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    claude_linux._read_staged_credential_under_lock(
                        staged,
                        owner_uid=os.getuid(),
                        refresh_lock_protocol=self.PROTOCOL,
                        timeout_seconds=0,
                    )

                self.assertIs(raised.exception, interruption)
                self.assertEqual(len(captured), 1)
                self._assert_assignment_interrupt_released_lock(captured[0])
            finally:
                for lease in captured:
                    if not lease.released:
                        lease._release(skip_abandoned=False)

    def test_staged_read_release_entry_interrupt_releases_owner_lease(
        self,
    ) -> None:
        captured: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
        armed = [True]
        interruption = KeyboardInterrupt(
            "injected staged-read refresh-lock release-entry interruption"
        )
        real_acquire = claude_linux.acquire_claude_refresh_lock

        def capture_acquire(
            *args: object,
            **kwargs: object,
        ) -> claude_refresh_lock.ClaudeRefreshLockLease:
            lease = real_acquire(*args, **kwargs)
            captured.append(lease)
            return lease

        with tempfile.TemporaryDirectory() as temporary:
            carrier_root = pathlib.Path(temporary) / "carrier"
            carrier_root.mkdir(mode=0o700)
            config_dir = carrier_root / "config"
            config_dir.mkdir(mode=0o700)
            credential_path = self._credential(
                config_dir / ".credentials.json",
                expires_at_ms=(time.time() + 7200) * 1000,
            )
            staged = claude_linux.StagedCredential(
                carrier_root,
                config_dir,
                credential_path,
                0.0,
            )
            try:
                with (
                    mock.patch.object(
                        claude_linux,
                        "acquire_claude_refresh_lock",
                        side_effect=capture_acquire,
                    ),
                    self._interrupt_release_call_entry(
                        armed=armed,
                        error=interruption,
                        target_lease=captured,
                    ),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    claude_linux._read_staged_credential_under_lock(
                        staged,
                        owner_uid=os.getuid(),
                        refresh_lock_protocol=self.PROTOCOL,
                        timeout_seconds=0,
                    )

                self.assertIs(raised.exception, interruption)
                self.assertFalse(armed[0])
                self.assertEqual(len(captured), 1)
                self._assert_assignment_interrupt_released_lock(captured[0])
            finally:
                for lease in captured:
                    if not lease.released:
                        lease._release(skip_abandoned=False)

    def test_staged_read_release_helper_entry_is_fail_closed(
        self,
    ) -> None:
        captured: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
        interruption = KeyboardInterrupt(
            "injected staged-read release-helper entry interruption"
        )
        real_acquire = claude_linux.acquire_claude_refresh_lock

        def capture_acquire(
            *args: object,
            **kwargs: object,
        ) -> claude_refresh_lock.ClaudeRefreshLockLease:
            lease = real_acquire(*args, **kwargs)
            captured.append(lease)
            return lease

        with tempfile.TemporaryDirectory() as temporary:
            carrier_root = pathlib.Path(temporary) / "carrier"
            carrier_root.mkdir(mode=0o700)
            config_dir = carrier_root / "config"
            config_dir.mkdir(mode=0o700)
            credential_path = self._credential(
                config_dir / ".credentials.json",
                expires_at_ms=(time.time() + 7200) * 1000,
            )
            staged = claude_linux.StagedCredential(
                carrier_root,
                config_dir,
                credential_path,
                0.0,
            )
            try:
                with (
                    mock.patch.object(
                        claude_linux,
                        "acquire_claude_refresh_lock",
                        side_effect=capture_acquire,
                    ),
                    self._interrupt_function_call_boundary(
                        claude_linux._read_staged_credential_under_lock,
                        callee_name=("_release_owned_claude_refresh_lock"),
                        window="entry",
                        target_lease=captured,
                        error=interruption,
                    ),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    claude_linux._read_staged_credential_under_lock(
                        staged,
                        owner_uid=os.getuid(),
                        refresh_lock_protocol=self.PROTOCOL,
                        timeout_seconds=0,
                    )

                self.assertIs(raised.exception, interruption)
                self.assertEqual(len(captured), 1)
                lease = captured[0]
                heartbeat = lease._heartbeat_thread
                self.assertIsNotNone(heartbeat)
                assert heartbeat is not None
                self.assertFalse(heartbeat.is_alive())
                self.assertTrue(lease.released or lease._deletion_prohibited)
                if lease.released:
                    self.assertTrue(all(not path.exists() for path in lease.paths))
                else:
                    self.assertTrue(all(path.is_dir() for path in lease.paths))
                    self._assert_refresh_lock_descriptors_closed(lease)
                    self.assertTrue(
                        getattr(
                            raised.exception,
                            ("_codex_claude_refresh_lock_descriptor_bound"),
                            False,
                        )
                        or getattr(
                            raised.exception,
                            "_codex_claude_refresh_lock_paths",
                            None,
                        )
                    )
            finally:
                for lease in captured:
                    self._dispose_refresh_lock_fixture(lease)

    def test_staged_read_release_return_interrupt_releases_owner_lease(
        self,
    ) -> None:
        captured: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
        armed = [False]
        interruption = KeyboardInterrupt(
            "injected staged-read refresh-lock release-return interruption"
        )
        real_acquire = claude_linux.acquire_claude_refresh_lock

        def acquire_and_arm(
            *args: object,
            **kwargs: object,
        ) -> claude_refresh_lock.ClaudeRefreshLockLease:
            lease = real_acquire(*args, **kwargs)
            captured.append(lease)
            armed[0] = True
            return lease

        with tempfile.TemporaryDirectory() as temporary:
            carrier_root = pathlib.Path(temporary) / "carrier"
            carrier_root.mkdir(mode=0o700)
            config_dir = carrier_root / "config"
            config_dir.mkdir(mode=0o700)
            credential_path = self._credential(
                config_dir / ".credentials.json",
                expires_at_ms=(time.time() + 7200) * 1000,
            )
            staged = claude_linux.StagedCredential(
                carrier_root,
                config_dir,
                credential_path,
                0.0,
            )
            try:
                with (
                    mock.patch.object(
                        claude_linux,
                        "acquire_claude_refresh_lock",
                        side_effect=acquire_and_arm,
                    ),
                    self._interrupt_acquire_assignment(
                        claude_linux._read_staged_credential_under_lock,
                        local_name="release_cleanup",
                        armed=armed,
                        error=interruption,
                    ),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    claude_linux._read_staged_credential_under_lock(
                        staged,
                        owner_uid=os.getuid(),
                        refresh_lock_protocol=self.PROTOCOL,
                        timeout_seconds=0,
                    )

                self.assertIs(raised.exception, interruption)
                self.assertFalse(armed[0])
                self.assertEqual(len(captured), 1)
                self._assert_assignment_interrupt_released_lock(captured[0])
            finally:
                for lease in captured:
                    if not lease.released:
                        lease._release(skip_abandoned=False)

    def test_writeback_assignment_interrupt_releases_owner_lease(
        self,
    ) -> None:
        captured: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
        armed = [False]
        interruption = KeyboardInterrupt(
            "injected writeback refresh-lock assignment interruption"
        )
        real_acquire = claude_linux.acquire_claude_refresh_lock

        def acquire_and_arm(
            *args: object,
            **kwargs: object,
        ) -> claude_refresh_lock.ClaudeRefreshLockLease:
            lease = real_acquire(*args, **kwargs)
            captured.append(lease)
            armed[0] = True
            return lease

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(time.time() - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            updated_path = self._credential(
                root / "updated.json",
                expires_at_ms=(time.time() + 7200) * 1000,
                access_token=self.SYNTH_ACCESS_A,
                refresh_token=self.SYNTH_REFRESH_B,
            )
            source_anchor = claude_linux._open_credential_directory_anchor(
                source,
                owner_uid=os.getuid(),
            )
            original_payload: bytearray | None = None
            updated_payload = bytearray(updated_path.read_bytes())
            try:
                (
                    original_payload,
                    _expires_at_ms,
                    original_identity,
                ) = claude_linux._read_valid_credential(
                    source,
                    owner_uid=os.getuid(),
                    now=0.0,
                    required_validity_seconds=0.0,
                    dir_fd=source_anchor.descriptor,
                )
                staged = claude_linux.StagedCredential(
                    root,
                    root,
                    updated_path,
                    0.0,
                )
                with (
                    mock.patch.object(
                        claude_linux,
                        "acquire_claude_refresh_lock",
                        side_effect=acquire_and_arm,
                    ),
                    self._interrupt_acquire_assignment(
                        claude_linux._writeback_refreshed_credential_impl,
                        local_name="refresh_lock",
                        armed=armed,
                        error=interruption,
                    ),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    claude_linux._writeback_refreshed_credential_impl(
                        source,
                        source_anchor,
                        staged,
                        original_payload,
                        original_identity,
                        source_anchor.identity,
                        owner_uid=os.getuid(),
                        refresh_lock_protocol=self.PROTOCOL,
                        staged_payload=updated_payload,
                    )

                self.assertIs(raised.exception, interruption)
                self.assertEqual(len(captured), 1)
                self._assert_assignment_interrupt_released_lock(captured[0])
            finally:
                if original_payload is not None:
                    original_payload[:] = b"\x00" * len(original_payload)
                updated_payload[:] = b"\x00" * len(updated_payload)
                source_anchor.close_if_owned()
                for lease in captured:
                    if not lease.released:
                        lease._release(skip_abandoned=False)

    def test_writeback_release_entry_interrupt_releases_owner_lease(
        self,
    ) -> None:
        captured: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
        armed = [True]
        interruption = KeyboardInterrupt(
            "injected writeback refresh-lock release-entry interruption"
        )
        real_acquire = claude_linux.acquire_claude_refresh_lock

        def capture_acquire(
            *args: object,
            **kwargs: object,
        ) -> claude_refresh_lock.ClaudeRefreshLockLease:
            lease = real_acquire(*args, **kwargs)
            captured.append(lease)
            return lease

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(time.time() - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            updated_path = self._credential(
                root / "updated.json",
                expires_at_ms=(time.time() + 7200) * 1000,
                access_token=self.SYNTH_ACCESS_A,
                refresh_token=self.SYNTH_REFRESH_B,
            )
            source_anchor = claude_linux._open_credential_directory_anchor(
                source,
                owner_uid=os.getuid(),
            )
            original_payload: bytearray | None = None
            updated_payload = bytearray(updated_path.read_bytes())
            try:
                (
                    original_payload,
                    _expires_at_ms,
                    original_identity,
                ) = claude_linux._read_valid_credential(
                    source,
                    owner_uid=os.getuid(),
                    now=0.0,
                    required_validity_seconds=0.0,
                    dir_fd=source_anchor.descriptor,
                )
                staged = claude_linux.StagedCredential(
                    root,
                    root,
                    updated_path,
                    0.0,
                )
                with (
                    mock.patch.object(
                        claude_linux,
                        "acquire_claude_refresh_lock",
                        side_effect=capture_acquire,
                    ),
                    self._interrupt_release_call_entry(
                        armed=armed,
                        error=interruption,
                        target_lease=captured,
                    ),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    claude_linux._writeback_refreshed_credential_impl(
                        source,
                        source_anchor,
                        staged,
                        original_payload,
                        original_identity,
                        source_anchor.identity,
                        owner_uid=os.getuid(),
                        refresh_lock_protocol=self.PROTOCOL,
                        staged_payload=updated_payload,
                    )

                self.assertIs(raised.exception, interruption)
                self.assertFalse(armed[0])
                self.assertEqual(len(captured), 1)
                self._assert_assignment_interrupt_released_lock(captured[0])
            finally:
                if original_payload is not None:
                    original_payload[:] = b"\x00" * len(original_payload)
                updated_payload[:] = b"\x00" * len(updated_payload)
                source_anchor.close_if_owned()
                for lease in captured:
                    if not lease.released:
                        lease._release(skip_abandoned=False)

    def test_writeback_release_helper_entry_is_fail_closed(self) -> None:
        captured: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
        interruption = KeyboardInterrupt(
            "injected writeback release-helper entry interruption"
        )
        real_acquire = claude_linux.acquire_claude_refresh_lock

        def capture_acquire(
            *args: object,
            **kwargs: object,
        ) -> claude_refresh_lock.ClaudeRefreshLockLease:
            lease = real_acquire(*args, **kwargs)
            captured.append(lease)
            return lease

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(time.time() - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            updated_path = self._credential(
                root / "updated.json",
                expires_at_ms=(time.time() + 7200) * 1000,
                access_token=self.SYNTH_ACCESS_A,
                refresh_token=self.SYNTH_REFRESH_B,
            )
            source_anchor = claude_linux._open_credential_directory_anchor(
                source,
                owner_uid=os.getuid(),
            )
            original_payload: bytearray | None = None
            updated_payload = bytearray(updated_path.read_bytes())
            try:
                (
                    original_payload,
                    _expires_at_ms,
                    original_identity,
                ) = claude_linux._read_valid_credential(
                    source,
                    owner_uid=os.getuid(),
                    now=0.0,
                    required_validity_seconds=0.0,
                    dir_fd=source_anchor.descriptor,
                )
                staged = claude_linux.StagedCredential(
                    root,
                    root,
                    updated_path,
                    0.0,
                )
                with (
                    mock.patch.object(
                        claude_linux,
                        "acquire_claude_refresh_lock",
                        side_effect=capture_acquire,
                    ),
                    self._interrupt_function_call_boundary(
                        claude_linux._writeback_refreshed_credential_impl,
                        callee_name=("_release_owned_claude_refresh_lock"),
                        window="entry",
                        target_lease=captured,
                        error=interruption,
                    ),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    claude_linux._writeback_refreshed_credential_impl(
                        source,
                        source_anchor,
                        staged,
                        original_payload,
                        original_identity,
                        source_anchor.identity,
                        owner_uid=os.getuid(),
                        refresh_lock_protocol=self.PROTOCOL,
                        staged_payload=updated_payload,
                    )

                self.assertIs(raised.exception, interruption)
                self.assertEqual(len(captured), 1)
                lease = captured[0]
                heartbeat = lease._heartbeat_thread
                self.assertIsNotNone(heartbeat)
                assert heartbeat is not None
                self.assertFalse(heartbeat.is_alive())
                self.assertTrue(lease.released or lease._deletion_prohibited)
                if lease.released:
                    self.assertTrue(all(not path.exists() for path in lease.paths))
                else:
                    self.assertTrue(all(path.is_dir() for path in lease.paths))
                    self._assert_refresh_lock_descriptors_closed(lease)
                    self.assertTrue(
                        getattr(
                            raised.exception,
                            ("_codex_claude_refresh_lock_descriptor_bound"),
                            False,
                        )
                        or getattr(
                            raised.exception,
                            "_codex_claude_refresh_lock_paths",
                            None,
                        )
                    )
            finally:
                if original_payload is not None:
                    original_payload[:] = b"\x00" * len(original_payload)
                updated_payload[:] = b"\x00" * len(updated_payload)
                source_anchor.close_if_owned()
                for lease in captured:
                    self._dispose_refresh_lock_fixture(lease)

    def test_writeback_release_return_interrupt_releases_owner_lease(
        self,
    ) -> None:
        captured: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
        armed = [False]
        interruption = KeyboardInterrupt(
            "injected writeback refresh-lock release-return interruption"
        )
        real_acquire = claude_linux.acquire_claude_refresh_lock

        def acquire_and_arm(
            *args: object,
            **kwargs: object,
        ) -> claude_refresh_lock.ClaudeRefreshLockLease:
            lease = real_acquire(*args, **kwargs)
            captured.append(lease)
            armed[0] = True
            return lease

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(time.time() - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            updated_path = self._credential(
                root / "updated.json",
                expires_at_ms=(time.time() + 7200) * 1000,
                access_token=self.SYNTH_ACCESS_A,
                refresh_token=self.SYNTH_REFRESH_B,
            )
            source_anchor = claude_linux._open_credential_directory_anchor(
                source,
                owner_uid=os.getuid(),
            )
            original_payload: bytearray | None = None
            updated_payload = bytearray(updated_path.read_bytes())
            try:
                (
                    original_payload,
                    _expires_at_ms,
                    original_identity,
                ) = claude_linux._read_valid_credential(
                    source,
                    owner_uid=os.getuid(),
                    now=0.0,
                    required_validity_seconds=0.0,
                    dir_fd=source_anchor.descriptor,
                )
                staged = claude_linux.StagedCredential(
                    root,
                    root,
                    updated_path,
                    0.0,
                )
                with (
                    mock.patch.object(
                        claude_linux,
                        "acquire_claude_refresh_lock",
                        side_effect=acquire_and_arm,
                    ),
                    self._interrupt_acquire_assignment(
                        claude_linux._writeback_refreshed_credential_impl,
                        local_name="refresh_lock_cleanup",
                        armed=armed,
                        error=interruption,
                    ),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    claude_linux._writeback_refreshed_credential_impl(
                        source,
                        source_anchor,
                        staged,
                        original_payload,
                        original_identity,
                        source_anchor.identity,
                        owner_uid=os.getuid(),
                        refresh_lock_protocol=self.PROTOCOL,
                        staged_payload=updated_payload,
                    )

                self.assertIs(raised.exception, interruption)
                self.assertFalse(armed[0])
                self.assertEqual(len(captured), 1)
                self._assert_assignment_interrupt_released_lock(captured[0])
            finally:
                if original_payload is not None:
                    original_payload[:] = b"\x00" * len(original_payload)
                updated_payload[:] = b"\x00" * len(updated_payload)
                source_anchor.close_if_owned()
                for lease in captured:
                    if not lease.released:
                        lease._release(skip_abandoned=False)

    def test_host_transaction_assignment_interrupt_retains_owner_lease(
        self,
    ) -> None:
        captured: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
        armed = [False]
        interruption = KeyboardInterrupt(
            "injected host refresh-lock assignment interruption"
        )
        real_acquire = claude_linux.acquire_claude_refresh_lock

        def acquire_and_arm(
            *args: object,
            **kwargs: object,
        ) -> claude_refresh_lock.ClaudeRefreshLockLease:
            lease = real_acquire(*args, **kwargs)
            captured.append(lease)
            armed[0] = True
            return lease

        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config_dir = root / "config"
            config_dir.mkdir(mode=0o700)
            source = self._credential(
                config_dir / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            generator = claude_linux._stage_claude_credentials_anchored.__wrapped__
            try:
                with (
                    mock.patch.object(
                        claude_linux,
                        "acquire_claude_refresh_lock",
                        side_effect=acquire_and_arm,
                    ),
                    self._interrupt_acquire_assignment(
                        generator,
                        local_name="host_refresh_lock",
                        armed=armed,
                        error=interruption,
                    ),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    with claude_linux.stage_claude_credentials(
                        source,
                        helper,
                        now=now,
                        refresh_lock_protocol=self.PROTOCOL,
                    ):
                        self.fail("assignment interruption reached staged credential")

                self.assertIs(raised.exception, interruption)
                self.assertEqual(len(captured), 1)
                self._assert_assignment_interrupt_retained_lock(captured[0])
                self.assertEqual(list(helper.iterdir()), [])
            finally:
                for lease in captured:
                    self._dispose_refresh_lock_fixture(lease)

    def test_host_transaction_release_entry_interrupt_retains_owner_lease(
        self,
    ) -> None:
        captured: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
        interruption = KeyboardInterrupt(
            "injected host refresh-lock release-entry interruption"
        )
        real_acquire = claude_linux.acquire_claude_refresh_lock
        coordinator_worker = (
            claude_linux._HostRefreshLockCleanupCoordinator._execute_worker_decision
        )

        def capture_acquire(
            *args: object,
            **kwargs: object,
        ) -> claude_refresh_lock.ClaudeRefreshLockLease:
            lease = real_acquire(*args, **kwargs)
            if pathlib.Path(args[0]) == source.parent:
                captured.append(lease)
            return lease

        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config_dir = root / "config"
            config_dir.mkdir(mode=0o700)
            source = self._credential(
                config_dir / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            try:
                with (
                    mock.patch.object(
                        claude_linux,
                        "acquire_claude_refresh_lock",
                        side_effect=capture_acquire,
                    ),
                    self._interrupt_cleanup_call_boundaries(
                        coordinator_worker,
                        target_lease=captured,
                        injections=[("_release", "entry", [interruption])],
                        include_new_threads=True,
                    ),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    with claude_linux.stage_claude_credentials(
                        source,
                        helper,
                        now=now,
                        refresh_lock_protocol=self.PROTOCOL,
                    ):
                        pass

                self.assertIs(raised.exception, interruption)
                self.assertEqual(len(captured), 1)
                self._assert_assignment_interrupt_retained_lock(captured[0])
                self.assertEqual(list(helper.iterdir()), [])
            finally:
                for lease in captured:
                    self._dispose_refresh_lock_fixture(lease)

    def test_host_transaction_release_helper_entry_is_fail_closed(
        self,
    ) -> None:
        captured: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
        interruption = KeyboardInterrupt(
            "injected host release-helper entry interruption"
        )
        real_acquire = claude_linux.acquire_claude_refresh_lock
        real_release = claude_refresh_lock.ClaudeRefreshLockLease._release
        coordinator_worker = (
            claude_linux._HostRefreshLockCleanupCoordinator._execute_worker_decision
        )

        def capture_acquire(
            *args: object,
            **kwargs: object,
        ) -> claude_refresh_lock.ClaudeRefreshLockLease:
            lease = real_acquire(*args, **kwargs)
            if pathlib.Path(args[0]) == source.parent:
                captured.append(lease)
            return lease

        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config_dir = root / "config"
            config_dir.mkdir(mode=0o700)
            source = self._credential(
                config_dir / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            helper = root / "helper"
            helper.mkdir(mode=0o700)

            def fail_host_release(
                lease: claude_refresh_lock.ClaudeRefreshLockLease,
                *,
                skip_abandoned: bool,
            ) -> None:
                if captured and lease is captured[0]:
                    raise claude_refresh_lock.ClaudeRefreshLockError(
                        "injected host release failure"
                    )
                real_release(
                    lease,
                    skip_abandoned=skip_abandoned,
                )

            try:
                with (
                    mock.patch.object(
                        claude_linux,
                        "acquire_claude_refresh_lock",
                        side_effect=capture_acquire,
                    ),
                    mock.patch.object(
                        claude_refresh_lock.ClaudeRefreshLockLease,
                        "_release",
                        autospec=True,
                        side_effect=fail_host_release,
                    ),
                    self._interrupt_function_call_boundary(
                        coordinator_worker,
                        callee_name="_retain_lease",
                        window="entry",
                        target_lease=captured,
                        error=interruption,
                        include_new_threads=True,
                    ),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    with claude_linux.stage_claude_credentials(
                        source,
                        helper,
                        now=now,
                        refresh_lock_protocol=self.PROTOCOL,
                    ):
                        pass

                self.assertIs(raised.exception, interruption)
                self.assertEqual(len(captured), 1)
                lease = captured[0]
                self._assert_assignment_interrupt_retained_lock(lease)
                self.assertTrue(
                    getattr(
                        raised.exception,
                        "_codex_claude_refresh_lock_descriptor_bound",
                        False,
                    )
                    or getattr(
                        raised.exception,
                        "_codex_claude_refresh_lock_paths",
                        None,
                    )
                )
                self.assertEqual(list(helper.iterdir()), [])
            finally:
                for lease in captured:
                    self._dispose_refresh_lock_fixture(lease)

    def test_host_transaction_release_return_interrupt_releases_owner_lease(
        self,
    ) -> None:
        captured: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
        armed = [False]
        interruption = KeyboardInterrupt(
            "injected host refresh-lock release-return interruption"
        )
        real_acquire = claude_linux.acquire_claude_refresh_lock

        def acquire_and_arm(
            *args: object,
            **kwargs: object,
        ) -> claude_refresh_lock.ClaudeRefreshLockLease:
            lease = real_acquire(*args, **kwargs)
            if pathlib.Path(args[0]) == source.parent:
                captured.append(lease)
                armed[0] = True
            return lease

        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config_dir = root / "config"
            config_dir.mkdir(mode=0o700)
            source = self._credential(
                config_dir / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            generator = claude_linux._stage_claude_credentials_anchored.__wrapped__
            try:
                with (
                    mock.patch.object(
                        claude_linux,
                        "acquire_claude_refresh_lock",
                        side_effect=acquire_and_arm,
                    ),
                    self._interrupt_acquire_assignment(
                        generator,
                        local_name="host_refresh_lock_cleanup",
                        armed=armed,
                        error=interruption,
                    ),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    with claude_linux.stage_claude_credentials(
                        source,
                        helper,
                        now=now,
                        refresh_lock_protocol=self.PROTOCOL,
                    ):
                        pass

                self.assertIs(raised.exception, interruption)
                self.assertFalse(armed[0])
                self.assertEqual(len(captured), 1)
                self._assert_assignment_interrupt_released_lock(captured[0])
                self.assertEqual(list(helper.iterdir()), [])
            finally:
                for lease in captured:
                    if not lease.released:
                        lease._release(skip_abandoned=False)

    def test_release_retry_abandons_and_preserves_control_flow_recovery(
        self,
    ) -> None:
        interruption = KeyboardInterrupt(
            "injected refresh-lock release-entry interruption"
        )
        retry_error = claude_refresh_lock.ClaudeRefreshLockError(
            "injected refresh-lock release retry failure"
        )
        recovery_path = "/fixture/config/.oauth_refresh.lock"
        abandonment_diagnostic = (
            claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive(
                "injected fail-closed refresh-lock abandonment"
            )
        )
        setattr(
            abandonment_diagnostic,
            "_codex_claude_refresh_lock_paths",
            (recovery_path,),
        )
        lease = mock.Mock(spec=["abandon", "release"])
        lease.release.side_effect = [interruption, retry_error]
        lease.abandon.return_value = abandonment_diagnostic
        owner = claude_refresh_lock.ClaudeRefreshLockOwner()
        owner._publish(lease)
        owner.transfer(lease)

        result = claude_linux._release_owned_claude_refresh_lock(
            owner,
            lease,
            message="cannot release fixture Claude refresh lock",
        )

        self.assertTrue(result.terminal)
        self.assertIs(result.error, interruption)
        self.assertEqual(
            getattr(
                interruption,
                "_codex_claude_refresh_lock_paths",
            ),
            (recovery_path,),
        )
        visible_diagnostics = [
            *getattr(interruption, "__notes__", ()),
        ]
        chained: BaseException | None = interruption.__cause__
        while chained is not None and len(visible_diagnostics) < 8:
            visible_diagnostics.append(str(chained))
            chained = chained.__cause__
        self.assertIn(
            "release retry failure",
            "\n".join(visible_diagnostics),
        )
        self.assertEqual(lease.release.call_count, 2)
        lease.abandon.assert_called_once_with(
            "cannot release fixture Claude refresh lock; two release attempts "
            "did not reach a terminal state"
        )

    def test_release_cleanup_accepts_settled_descriptor_residue_as_terminal(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config_dir = pathlib.Path(temporary) / "config"
            config_dir.mkdir(mode=0o700)
            owner = claude_refresh_lock.ClaudeRefreshLockOwner()
            lease = claude_linux.acquire_claude_refresh_lock(
                config_dir,
                protocol=self.PROTOCOL,
                owner=owner,
            )
            owner.transfer(lease)
            descriptors = {
                *(lock.descriptor for lock in lease._locks),
                lease._legacy_parent_anchor.descriptor,
                lease._config_anchor.descriptor,
            }
            failed_descriptor = next(iter(descriptors))
            real_close = os.close
            failed = False
            close_attempts: dict[int, int] = {}

            def fail_one_close(descriptor: int) -> None:
                nonlocal failed
                close_attempts[descriptor] = close_attempts.get(descriptor, 0) + 1
                if descriptor == failed_descriptor and not failed:
                    failed = True
                    raise OSError(errno.EIO, "injected descriptor close failure")
                real_close(descriptor)

            release_error = KeyboardInterrupt("injected refresh-lock release failure")
            try:
                with (
                    mock.patch.object(
                        lease,
                        "release",
                        side_effect=[release_error, release_error],
                    ),
                    mock.patch.object(
                        claude_refresh_lock.os,
                        "close",
                        side_effect=fail_one_close,
                    ),
                ):
                    result = claude_linux._release_owned_claude_refresh_lock(
                        owner,
                        lease,
                        message="cannot release fixture Claude refresh lock",
                    )

                self.assertTrue(failed)
                self.assertTrue(result.terminal)
                self.assertIs(result.error, release_error)
                self.assertFalse(lease.released)
                self.assertTrue(all(path.is_dir() for path in lease.paths))
                self.assertEqual(close_attempts[failed_descriptor], 1)
                self.assertIn(
                    failed_descriptor,
                    lease._abandonment_descriptors_residue,
                )
                os.fstat(failed_descriptor)
                with (
                    mock.patch.object(
                        claude_refresh_lock.os,
                        "fstat",
                        side_effect=AssertionError(
                            "settled Linux cleanup rechecked descriptors"
                        ),
                    ),
                    mock.patch.object(
                        claude_refresh_lock.os,
                        "close",
                        side_effect=AssertionError(
                            "settled Linux cleanup reclosed descriptors"
                        ),
                    ),
                ):
                    terminal, diagnostic = (
                        claude_linux._claude_refresh_lock_retention_terminal(lease)
                    )
                self.assertTrue(terminal)
                self.assertIs(
                    diagnostic,
                    lease._descriptor_bound_cleanup_fallback,
                )
            finally:
                try:
                    real_close(failed_descriptor)
                except OSError:
                    pass
                for path in reversed(lease.paths):
                    if path.exists():
                        path.rmdir()

    def test_abandon_helper_never_attaches_resumable_promoted_paths(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            home = root / "home"
            home.mkdir(mode=0o700)
            config_dir = home / "config"
            config_dir.mkdir(mode=0o700)
            owner = claude_refresh_lock.ClaudeRefreshLockOwner()
            lease = claude_linux.acquire_claude_refresh_lock(
                config_dir,
                protocol=self.PROTOCOL,
                owner=owner,
            )
            owner.transfer(lease)
            lexical_paths = lease.paths
            descriptors = {
                *(lock.descriptor for lock in lease._locks),
                lease._legacy_parent_anchor.descriptor,
                lease._config_anchor.descriptor,
            }
            real_close = os.close
            close_counts: dict[int, int] = {}
            close_interruption = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            primary_error = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
            close_interrupted = False
            abandon_calls = 0
            retained_home = root / "retained-home"
            replacement_primary = config_dir / ".oauth_refresh.lock"
            replacement_legacy = pathlib.Path(str(config_dir) + ".lock")
            live_marker = replacement_primary / "live-owner"
            real_abandon = lease.abandon

            def close_then_interrupt(descriptor: int) -> None:
                nonlocal close_interrupted
                close_counts[descriptor] = close_counts.get(descriptor, 0) + 1
                real_close(descriptor)
                if not close_interrupted:
                    close_interrupted = True
                    raise close_interruption

            def abandon_then_retarget(
                reason: str,
            ) -> claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive:
                nonlocal abandon_calls
                abandon_calls += 1
                if abandon_calls != 1:
                    return real_abandon(reason)
                try:
                    return real_abandon(reason)
                finally:
                    home.rename(retained_home)
                    home.mkdir(mode=0o700)
                    config_dir.mkdir(mode=0o700)
                    replacement_primary.mkdir(mode=0o700)
                    replacement_legacy.mkdir(mode=0o700)
                    live_marker.write_text(
                        "replacement\n",
                        encoding="utf-8",
                    )

            with lease._state_lock:
                lease._deletion_prohibited = True
                lease._heartbeat_stop.set()
            try:
                with (
                    mock.patch.object(
                        lease,
                        "abandon",
                        side_effect=abandon_then_retarget,
                    ),
                    mock.patch.object(
                        claude_refresh_lock.os,
                        "close",
                        side_effect=close_then_interrupt,
                    ),
                ):
                    result = claude_linux._abandon_owned_claude_refresh_lock(
                        lease,
                        reason="fixture release could not complete",
                        primary_error=primary_error,
                        message="cannot abandon fixture Claude refresh lock",
                    )

                self.assertTrue(result.terminal)
                self.assertIs(result.error, primary_error)
                self.assertEqual(abandon_calls, 2)
                self.assertTrue(close_interrupted)
                self.assertEqual(set(close_counts), descriptors)
                self.assertTrue(all(count == 1 for count in close_counts.values()))
                self.assertIs(
                    lease._abandonment_cleanup_lifecycle,
                    claude_refresh_lock._AbandonmentCleanupLifecycle.SETTLED,
                )
                diagnostic = lease._cleanup_inconclusive
                self.assertIsNotNone(diagnostic)
                assert diagnostic is not None
                for error in (primary_error, close_interruption, diagnostic):
                    self.assertTrue(
                        claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                            error
                        )
                    )
                    self.assertFalse(
                        hasattr(
                            error,
                            "_codex_claude_refresh_lock_paths",
                        )
                    )
                    self.assertIsNone(
                        claude_refresh_lock._refresh_lock_recovery_paths(error)
                    )
                    visible = [
                        str(error),
                        *getattr(error, "__notes__", ()),
                    ]
                    detail = getattr(error, "detail", None)
                    if isinstance(detail, str):
                        visible.append(detail)
                    for path in lexical_paths:
                        self.assertNotIn(str(path), "\n".join(visible))
                retained_config = retained_home / "config"
                self.assertTrue((retained_config / ".oauth_refresh.lock").is_dir())
                self.assertTrue(pathlib.Path(str(retained_config) + ".lock").is_dir())
                self.assertEqual(
                    live_marker.read_text(encoding="utf-8"),
                    "replacement\n",
                )
            finally:
                for descriptor in descriptors:
                    try:
                        real_close(descriptor)
                    except OSError:
                        pass

    def test_abandon_helper_retry_hides_preexisting_promoted_paths(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            home = root / "home"
            home.mkdir(mode=0o700)
            config_dir = home / "config"
            config_dir.mkdir(mode=0o700)
            owner = claude_refresh_lock.ClaudeRefreshLockOwner()
            lease = claude_linux.acquire_claude_refresh_lock(
                config_dir,
                protocol=self.PROTOCOL,
                owner=owner,
            )
            owner.transfer(lease)
            lexical_paths = lease.paths
            descriptors = {
                *(lock.descriptor for lock in lease._locks),
                lease._legacy_parent_anchor.descriptor,
                lease._config_anchor.descriptor,
            }
            retained_home = root / "retained-home"
            replacement_primary = config_dir / ".oauth_refresh.lock"
            replacement_legacy = pathlib.Path(str(config_dir) + ".lock")
            live_marker = replacement_primary / "live-owner"
            first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
            with lease._state_lock:
                lease._publish_abandonment_state()
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            heartbeat.join(timeout=2.0)
            self.assertFalse(heartbeat.is_alive())
            promoted = lease._cleanup_inconclusive_fallback
            lease._promote_cleanup_inconclusive_paths(
                promoted,
                reason="legacy promoted recovery state",
                authoritative_paths=tuple(str(path) for path in lexical_paths),
            )
            self.assertEqual(
                claude_refresh_lock._refresh_lock_recovery_paths(promoted),
                tuple(str(path) for path in lexical_paths),
            )
            self.assertIs(
                lease._abandonment_cleanup_lifecycle,
                claude_refresh_lock._AbandonmentCleanupLifecycle.RESUMABLE,
            )

            home.rename(retained_home)
            home.mkdir(mode=0o700)
            config_dir.mkdir(mode=0o700)
            replacement_primary.mkdir(mode=0o700)
            replacement_legacy.mkdir(mode=0o700)
            live_marker.write_text("replacement\n", encoding="utf-8")
            close_counts: dict[int, int] = {}
            real_close = os.close

            def record_close(descriptor: int) -> None:
                close_counts[descriptor] = close_counts.get(descriptor, 0) + 1
                real_close(descriptor)

            try:
                with mock.patch.object(
                    claude_refresh_lock.os,
                    "close",
                    side_effect=record_close,
                ):
                    result = claude_linux._abandon_owned_claude_refresh_lock(
                        lease,
                        reason="resume after ancestor retarget",
                        primary_error=first,
                        message="cannot abandon fixture Claude refresh lock",
                    )

                self.assertTrue(result.terminal)
                self.assertIs(result.error, first)
                self.assertEqual(set(close_counts), descriptors)
                self.assertTrue(all(count == 1 for count in close_counts.values()))
                retained_config = retained_home / "config"
                for error in (first, lease._cleanup_inconclusive):
                    self.assertIsNotNone(error)
                    assert error is not None
                    self.assertTrue(
                        claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                            error
                        )
                    )
                    self.assertFalse(hasattr(error, "_codex_claude_refresh_lock_paths"))
                    self.assertIsNone(
                        claude_refresh_lock._refresh_lock_recovery_paths(error)
                    )
                    rendered = [
                        str(error),
                        *getattr(error, "__notes__", ()),
                        *traceback.TracebackException.from_exception(error).format(
                            chain=True
                        ),
                    ]
                    detail = getattr(error, "detail", None)
                    if isinstance(detail, str):
                        rendered.append(detail)
                    retained_paths = (
                        retained_config / ".oauth_refresh.lock",
                        pathlib.Path(str(retained_config) + ".lock"),
                    )
                    for path in (*lexical_paths, *retained_paths):
                        self.assertNotIn(str(path), "\n".join(rendered))
                self.assertTrue((retained_config / ".oauth_refresh.lock").is_dir())
                self.assertTrue(pathlib.Path(str(retained_config) + ".lock").is_dir())
                self.assertEqual(
                    live_marker.read_text(encoding="utf-8"),
                    "replacement\n",
                )
            finally:
                for descriptor in descriptors:
                    try:
                        real_close(descriptor)
                    except OSError:
                        pass

    def test_recovery_evidence_reads_are_direct_and_bounded(self) -> None:
        consumers = {
            claude_linux._abandon_owned_claude_refresh_lock: 2,
            claude_linux._release_owned_claude_refresh_lock: 1,
            claude_linux._recover_prearmed_claude_refresh_lock_release: 1,
            claude_linux._writeback_refreshed_credential_impl: 2,
            claude_linux._read_staged_credential_under_lock: 1,
            claude_linux._retain_unmasked_credential_cleanup: 1,
            claude_linux._stage_claude_credentials_anchored.__wrapped__: 4,
        }
        source = pathlib.Path(claude_linux.__file__).read_text(encoding="utf-8")
        self.assertEqual(source.count("_retention_recovery_evidence"), 12)
        self.assertNotIn("_retention_recovery_evidence(", source)

        total_reads = 0
        for function, expected_reads in consumers.items():
            with self.subTest(function=function.__name__):
                instructions = tuple(dis.get_instructions(function))
                read_indices = [
                    index
                    for index, instruction in enumerate(instructions)
                    if instruction.argval == "_retention_recovery_evidence"
                ]
                read_lines: set[int] = set()
                current_line = function.__code__.co_firstlineno
                for instruction in instructions:
                    positions = getattr(instruction, "positions", None)
                    instruction_line = (
                        positions.lineno
                        if positions is not None
                        else instruction.starts_line
                    )
                    if instruction_line is not None:
                        current_line = instruction_line
                    if instruction.argval == "_retention_recovery_evidence":
                        read_lines.add(current_line)
                self.assertEqual(len(read_lines), expected_reads)
                total_reads += len(read_lines)
                for index in read_indices:
                    self.assertEqual(instructions[index].opname, "LOAD_ATTR")
                    self.assertLess(index + 1, len(instructions))
                    self.assertEqual(
                        instructions[index + 1].opname,
                        "STORE_FAST",
                    )
        self.assertEqual(total_reads, 12)

    def test_release_retry_evidence_cannot_alias_promoted_fallback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config_dir = pathlib.Path(temporary).resolve() / "config"
            config_dir.mkdir(mode=0o700)
            owner = claude_refresh_lock.ClaudeRefreshLockOwner()
            lease = claude_linux.acquire_claude_refresh_lock(
                config_dir,
                protocol=self.PROTOCOL,
                owner=owner,
            )
            owner.transfer(lease)
            lexical_paths = tuple(str(path) for path in lease.paths)
            initial_evidence = lease._retention_recovery_evidence
            self.assertIs(
                initial_evidence,
                lease._descriptor_bound_cleanup_fallback,
            )
            release_calls = 0
            abandon_calls = 0

            def fail_release() -> None:
                nonlocal release_calls
                release_calls += 1
                raise claude_refresh_lock.ClaudeRefreshLockError(
                    f"injected release failure {release_calls}"
                )

            def promote_then_fail_abandon(
                _lease: claude_refresh_lock.ClaudeRefreshLockLease,
                **_kwargs: object,
            ) -> claude_linux._ClaudeRefreshLockCleanupResult:
                nonlocal abandon_calls
                abandon_calls += 1
                if abandon_calls == 1:
                    fallback = lease._cleanup_inconclusive_fallback
                    with lease._state_lock:
                        lease._cleanup_inconclusive = fallback
                    lease._promote_cleanup_inconclusive_paths(
                        fallback,
                        reason="promoted during helper retry",
                        authoritative_paths=lexical_paths,
                    )
                raise claude_refresh_lock.ClaudeRefreshLockError(
                    f"injected abandonment boundary failure {abandon_calls}"
                )

            try:
                with (
                    mock.patch.object(
                        lease,
                        "release",
                        side_effect=fail_release,
                    ),
                    mock.patch.object(
                        claude_linux,
                        "_abandon_owned_claude_refresh_lock",
                        side_effect=promote_then_fail_abandon,
                    ),
                ):
                    result = claude_linux._release_owned_claude_refresh_lock(
                        owner,
                        lease,
                        message="cannot release fixture Claude refresh lock",
                    )

                self.assertFalse(result.terminal)
                self.assertIsNotNone(result.error)
                assert result.error is not None
                self.assertEqual(release_calls, 4)
                self.assertEqual(abandon_calls, 2)
                self.assertEqual(
                    claude_refresh_lock._refresh_lock_recovery_paths(
                        lease._cleanup_inconclusive_fallback
                    ),
                    lexical_paths,
                )
                self.assertTrue(
                    claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                        initial_evidence
                    )
                )
                self.assertIsNone(
                    claude_refresh_lock._refresh_lock_recovery_paths(initial_evidence)
                )
                self.assertIs(
                    getattr(
                        result.error,
                        "_codex_claude_refresh_lock_cleanup_evidence",
                        None,
                    ),
                    None,
                )
                self.assertTrue(
                    claude_refresh_lock._has_descriptor_bound_refresh_lock_cleanup(
                        result.error
                    )
                )
                self.assertFalse(
                    hasattr(
                        result.error,
                        "_codex_claude_refresh_lock_paths",
                    )
                )
                self.assertIsNone(
                    claude_refresh_lock._refresh_lock_recovery_paths(result.error)
                )
                visible = [
                    str(result.error),
                    *getattr(result.error, "__notes__", ()),
                ]
                detail = getattr(result.error, "detail", None)
                if isinstance(detail, str):
                    visible.append(detail)
                for path in lexical_paths:
                    self.assertNotIn(path, "\n".join(visible))
            finally:
                self._dispose_refresh_lock_fixture(lease)

    def test_released_lease_has_no_synthetic_none_recovery_diagnostic(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config_dir = pathlib.Path(temporary).resolve() / "config"
            config_dir.mkdir(mode=0o700)
            owner = claude_refresh_lock.ClaudeRefreshLockOwner()
            lease = claude_linux.acquire_claude_refresh_lock(
                config_dir,
                protocol=self.PROTOCOL,
                owner=owner,
            )
            owner.transfer(lease)
            lease.release()
            evidence = lease._retention_recovery_evidence
            self.assertIsNone(evidence)
            interruption = KeyboardInterrupt("released helper boundary")

            claude_linux._attach_host_refresh_lock_recovery(
                interruption,
                evidence,
            )

            self.assertIsNone(interruption.__cause__)
            self.assertIsNone(interruption.__context__)
            self.assertFalse(hasattr(interruption, "__notes__"))
            self.assertFalse(
                hasattr(
                    interruption,
                    "_codex_claude_refresh_lock_descriptor_bound",
                )
            )
            self.assertFalse(
                hasattr(
                    interruption,
                    "_codex_claude_refresh_lock_paths",
                )
            )

    def test_resumable_retention_is_not_terminal_after_descriptors_close(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config_dir = pathlib.Path(temporary) / "config"
            config_dir.mkdir(mode=0o700)
            owner = claude_refresh_lock.ClaudeRefreshLockOwner()
            lease = claude_linux.acquire_claude_refresh_lock(
                config_dir,
                protocol=self.PROTOCOL,
                owner=owner,
            )
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            lease._heartbeat_stop.set()
            heartbeat.join(timeout=1.0)
            self.assertFalse(heartbeat.is_alive())
            with lease._state_lock:
                lease._publish_abandonment_state()
            descriptors = {
                *(lock.descriptor for lock in lease._locks),
                lease._legacy_parent_anchor.descriptor,
                lease._config_anchor.descriptor,
            }
            for descriptor in descriptors:
                os.close(descriptor)

            with mock.patch.object(
                claude_linux.os,
                "fstat",
                side_effect=AssertionError(
                    "Linux retention state inferred from descriptor state"
                ),
            ):
                terminal, diagnostic = (
                    claude_linux._claude_refresh_lock_retention_terminal(lease)
                )

            self.assertFalse(terminal)
            self.assertIs(
                diagnostic,
                lease._descriptor_bound_cleanup_fallback,
            )
            self.assertIs(
                lease._abandonment_cleanup_lifecycle,
                claude_refresh_lock._AbandonmentCleanupLifecycle.RESUMABLE,
            )
            for path in reversed(lease.paths):
                path.rmdir()

    def test_repeated_release_and_abandon_entry_interruptions_retain_lock(
        self,
    ) -> None:
        release_interrupts = [
            KeyboardInterrupt("injected first release-entry interruption"),
            KeyboardInterrupt("injected second release-entry interruption"),
        ]
        abandon_interrupts = [
            KeyboardInterrupt("injected first abandon-entry interruption"),
            KeyboardInterrupt("injected second abandon-entry interruption"),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            config_dir = pathlib.Path(temporary) / "config"
            config_dir.mkdir(mode=0o700)
            owner = claude_refresh_lock.ClaudeRefreshLockOwner()
            lease = claude_linux.acquire_claude_refresh_lock(
                config_dir,
                protocol=self.PROTOCOL,
                owner=owner,
            )
            owner.transfer(lease)
            real_release = lease.release

            def interrupt_release_entry() -> None:
                if release_interrupts:
                    raise release_interrupts.pop(0)
                real_release()

            try:
                first_interruption = release_interrupts[0]
                with (
                    mock.patch.object(
                        lease,
                        "release",
                        side_effect=interrupt_release_entry,
                    ),
                    mock.patch.object(
                        lease,
                        "abandon",
                        side_effect=abandon_interrupts,
                    ),
                ):
                    result = claude_linux._release_owned_claude_refresh_lock(
                        owner,
                        lease,
                        message=("cannot release fixture Claude refresh lock"),
                    )

                heartbeat = lease._heartbeat_thread
                self.assertIsNotNone(heartbeat)
                assert heartbeat is not None
                self.assertTrue(result.terminal)
                self.assertIs(result.error, first_interruption)
                self.assertTrue(lease._deletion_prohibited)
                self.assertFalse(heartbeat.is_alive())
                self.assertTrue(all(path.is_dir() for path in lease.paths))
                self._assert_refresh_lock_descriptors_closed(lease)
                self.assertTrue(
                    getattr(
                        result.error,
                        "_codex_claude_refresh_lock_descriptor_bound",
                        False,
                    )
                )
            finally:
                self._dispose_refresh_lock_fixture(lease)

    def test_repeated_release_return_interruptions_recognize_release(
        self,
    ) -> None:
        release_interrupts = [
            KeyboardInterrupt("injected first release-return interruption"),
            KeyboardInterrupt("injected second release-return interruption"),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            config_dir = pathlib.Path(temporary) / "config"
            config_dir.mkdir(mode=0o700)
            owner = claude_refresh_lock.ClaudeRefreshLockOwner()
            lease = claude_linux.acquire_claude_refresh_lock(
                config_dir,
                protocol=self.PROTOCOL,
                owner=owner,
            )
            owner.transfer(lease)
            real_release = lease.release

            def release_then_interrupt() -> None:
                real_release()
                raise release_interrupts.pop(0)

            try:
                first_interruption = release_interrupts[0]
                with mock.patch.object(
                    lease,
                    "release",
                    side_effect=release_then_interrupt,
                ):
                    result = claude_linux._release_owned_claude_refresh_lock(
                        owner,
                        lease,
                        message=("cannot release fixture Claude refresh lock"),
                    )

                self.assertTrue(result.terminal)
                self.assertIs(result.error, first_interruption)
                self.assertTrue(lease.released)
                self.assertTrue(all(not path.exists() for path in lease.paths))
            finally:
                self._dispose_refresh_lock_fixture(lease)

    def test_pending_operation_handoff_blocks_linux_terminal_fast_paths(
        self,
    ) -> None:
        class InterruptedOperationLock:
            def __init__(
                self,
                *interruptions: BaseException,
            ) -> None:
                self._lock = threading.RLock()
                self._interruptions = interruptions
                self.release_calls = 0

            def _is_owned(self) -> bool:
                return self._lock._is_owned()

            def acquire(self, *, timeout: float = -1.0) -> bool:
                return self._lock.acquire(timeout=timeout)

            def release(self) -> None:
                self.release_calls += 1
                if self.release_calls <= len(self._interruptions):
                    raise self._interruptions[self.release_calls - 1]
                self._lock.release()

        cases = (
            "release-catch",
            "release-exhausted",
            "abandon-entry",
            "prearmed-recovery",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                config_dir = pathlib.Path(temporary) / "config"
                config_dir.mkdir(mode=0o700)
                owner = claude_refresh_lock.ClaudeRefreshLockOwner()
                lease = claude_linux.acquire_claude_refresh_lock(
                    config_dir,
                    protocol=self.PROTOCOL,
                    owner=owner,
                )
                owner.transfer(lease)
                heartbeat = lease._heartbeat_thread
                assert heartbeat is not None
                lease._heartbeat_stop.set()
                heartbeat.join(timeout=2.0)
                self.assertFalse(heartbeat.is_alive())
                first = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                second = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
                third = claude_refresh_lock.ForwardedSignal(signal.SIGTERM)
                fourth = claude_refresh_lock.ForwardedSignal(signal.SIGINT)
                interruptions = (
                    (first, second)
                    if case == "release-catch"
                    else (first, second, third, fourth)
                )
                operation_lock = InterruptedOperationLock(*interruptions)
                lease._operation_lock = operation_lock

                try:
                    if case != "release-catch":
                        with self.assertRaises(
                            claude_refresh_lock.ForwardedSignal
                        ) as released:
                            lease.release()

                        self.assertIs(released.exception, first)
                        self.assertTrue(lease.released)
                        self.assertEqual(operation_lock.release_calls, 4)
                        self.assertIsNotNone(lease._pending_operation_handoff)

                    if case == "release-catch":
                        result = claude_linux._release_owned_claude_refresh_lock(
                            owner,
                            lease,
                            message=(
                                "cannot release pending fixture Claude refresh lock"
                            ),
                        )
                    elif case == "release-exhausted":
                        failures = [
                            KeyboardInterrupt("first helper release failure"),
                            KeyboardInterrupt("second helper release failure"),
                        ]
                        with mock.patch.object(
                            lease,
                            "release",
                            side_effect=failures,
                        ) as release_call:
                            result = claude_linux._release_owned_claude_refresh_lock(
                                owner,
                                lease,
                                message=(
                                    "cannot release exhausted pending "
                                    "fixture Claude refresh lock"
                                ),
                            )
                        self.assertEqual(release_call.call_count, 2)
                    elif case == "abandon-entry":
                        with lease._state_lock:
                            lease._deletion_prohibited = True
                            lease._heartbeat_stop.set()
                        result = claude_linux._abandon_owned_claude_refresh_lock(
                            lease,
                            reason="resume released pending fixture",
                            primary_error=first,
                            message=(
                                "cannot abandon pending fixture Claude refresh lock"
                            ),
                        )
                    else:
                        with lease._state_lock:
                            lease._deletion_prohibited = True
                            lease._heartbeat_stop.set()
                        result = (
                            claude_linux._recover_prearmed_claude_refresh_lock_release(
                                owner,
                                lease,
                                boundary_error=first,
                                message=(
                                    "cannot recover pending fixture Claude refresh lock"
                                ),
                            )
                        )

                    self.assertTrue(result.terminal)
                    expected_release_calls = 3 if case == "release-catch" else 5
                    self.assertEqual(
                        operation_lock.release_calls,
                        expected_release_calls,
                    )
                    self.assertIsNone(lease._pending_operation_handoff)
                    snapshot = lease.retention_snapshot()
                    self.assertTrue(snapshot.terminal)
                    self.assertTrue(snapshot.verified_closed)
                finally:
                    if operation_lock._is_owned():
                        operation_lock._lock.release()
                    self._dispose_refresh_lock_fixture(lease)

    def test_repeated_abandon_return_interruptions_recognize_abandonment(
        self,
    ) -> None:
        release_interrupts = [
            KeyboardInterrupt("injected first release-entry interruption"),
            KeyboardInterrupt("injected second release-entry interruption"),
        ]
        abandon_interrupts = [
            KeyboardInterrupt("injected first abandon-return interruption"),
            KeyboardInterrupt("injected second abandon-return interruption"),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            config_dir = pathlib.Path(temporary) / "config"
            config_dir.mkdir(mode=0o700)
            owner = claude_refresh_lock.ClaudeRefreshLockOwner()
            lease = claude_linux.acquire_claude_refresh_lock(
                config_dir,
                protocol=self.PROTOCOL,
                owner=owner,
            )
            owner.transfer(lease)
            real_abandon = lease.abandon

            def abandon_then_interrupt(reason: str) -> None:
                real_abandon(reason)
                raise abandon_interrupts.pop(0)

            try:
                first_interruption = release_interrupts[0]
                with (
                    mock.patch.object(
                        lease,
                        "release",
                        side_effect=release_interrupts,
                    ),
                    mock.patch.object(
                        lease,
                        "abandon",
                        side_effect=abandon_then_interrupt,
                    ),
                ):
                    result = claude_linux._release_owned_claude_refresh_lock(
                        owner,
                        lease,
                        message=("cannot release fixture Claude refresh lock"),
                    )

                heartbeat = lease._heartbeat_thread
                self.assertIsNotNone(heartbeat)
                assert heartbeat is not None
                self.assertTrue(result.terminal)
                self.assertIs(result.error, first_interruption)
                self.assertTrue(lease._deletion_prohibited)
                self.assertFalse(heartbeat.is_alive())
                self.assertTrue(all(path.is_dir() for path in lease.paths))
                self._assert_refresh_lock_descriptors_closed(lease)
                self.assertTrue(
                    getattr(
                        result.error,
                        "_codex_claude_refresh_lock_paths",
                        None,
                    )
                    or getattr(
                        result.error,
                        "_codex_claude_refresh_lock_descriptor_bound",
                        False,
                    )
                )
            finally:
                self._dispose_refresh_lock_fixture(lease)

    def test_release_fallback_prearms_abandon_helper_boundaries(
        self,
    ) -> None:
        release_helper = claude_linux._release_owned_claude_refresh_lock
        for boundary in ("helper-entry", "helper-pre-latch"):
            with self.subTest(boundary=boundary):
                with tempfile.TemporaryDirectory() as temporary:
                    config_dir = pathlib.Path(temporary) / "config"
                    config_dir.mkdir(mode=0o700)
                    owner = claude_refresh_lock.ClaudeRefreshLockOwner()
                    lease = claude_linux.acquire_claude_refresh_lock(
                        config_dir,
                        protocol=self.PROTOCOL,
                        owner=owner,
                    )
                    owner.transfer(lease)
                    target_lease = [lease]
                    release_failures = [
                        claude_refresh_lock.ClaudeRefreshLockError(
                            "injected first release failure"
                        ),
                        claude_refresh_lock.ClaudeRefreshLockError(
                            "injected second release failure"
                        ),
                    ]
                    real_release = lease.release

                    def fail_then_resume_release() -> None:
                        if release_failures:
                            raise release_failures.pop(0)
                        real_release()

                    interruption = KeyboardInterrupt(
                        f"injected release fallback {boundary} interruption"
                    )
                    pre_latch_armed: list[bool] | None = None
                    if boundary == "helper-entry":
                        interrupt_context = self._interrupt_function_call_boundary(
                            release_helper,
                            callee_name=("_abandon_owned_claude_refresh_lock"),
                            window="entry",
                            target_lease=target_lease,
                            error=interruption,
                        )
                    else:
                        real_retention_snapshot = lease.retention_snapshot
                        pre_latch_armed = [True]

                        def interrupt_prearmed_retention_snapshot():
                            assert pre_latch_armed is not None
                            if (
                                pre_latch_armed[0]
                                and lease._deletion_prohibited
                                and lease._heartbeat_stop.is_set()
                            ):
                                pre_latch_armed[0] = False
                                raise interruption
                            return real_retention_snapshot()

                        interrupt_context = mock.patch.object(
                            lease,
                            "retention_snapshot",
                            side_effect=(interrupt_prearmed_retention_snapshot),
                        )
                    try:
                        with (
                            mock.patch.object(
                                lease,
                                "release",
                                side_effect=fail_then_resume_release,
                            ),
                            interrupt_context,
                        ):
                            result = release_helper(
                                owner,
                                lease,
                                message=("cannot release fixture Claude refresh lock"),
                            )

                        heartbeat = lease._heartbeat_thread
                        self.assertIsNotNone(heartbeat)
                        assert heartbeat is not None
                        self.assertTrue(result.terminal)
                        self.assertIs(result.error, interruption)
                        self.assertTrue(lease._deletion_prohibited)
                        self.assertFalse(heartbeat.is_alive())
                        self.assertTrue(all(path.is_dir() for path in lease.paths))
                        self._assert_refresh_lock_descriptors_closed(lease)
                        self.assertTrue(
                            getattr(
                                result.error,
                                ("_codex_claude_refresh_lock_descriptor_bound"),
                                False,
                            )
                            or getattr(
                                result.error,
                                "_codex_claude_refresh_lock_paths",
                                None,
                            )
                        )
                        if pre_latch_armed is not None:
                            self.assertFalse(pre_latch_armed[0])
                    finally:
                        self._dispose_refresh_lock_fixture(lease)

    def test_carrier_cleanup_abandon_call_boundaries_are_fail_closed(
        self,
    ) -> None:
        retain_helper = claude_linux._HostRefreshLockCleanupCoordinator._retain_lease
        coordinator_worker = (
            claude_linux._HostRefreshLockCleanupCoordinator._execute_worker_decision
        )
        boundaries = (
            "abandon-entry",
            "abandon-return",
            "retain-entry",
            "retain-return",
            "snapshot-entry",
        )
        for boundary in boundaries:
            with self.subTest(boundary=boundary):
                now = time.time()
                with tempfile.TemporaryDirectory() as temporary:
                    root = pathlib.Path(temporary)
                    config_dir = root / "host-config"
                    config_dir.mkdir(mode=0o700)
                    helper = root / "helper"
                    helper.mkdir(mode=0o700)
                    source = self._credential(
                        config_dir / ".credentials.json",
                        expires_at_ms=(now - 60) * 1000,
                    )
                    captured: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
                    staged: claude_linux.StagedCredential | None = None
                    real_acquire = claude_linux.acquire_claude_refresh_lock

                    def capture_host_lock(
                        *args: object,
                        **kwargs: object,
                    ) -> claude_refresh_lock.ClaudeRefreshLockLease:
                        lease = real_acquire(*args, **kwargs)
                        if pathlib.Path(args[0]) == source.parent:
                            captured.append(lease)
                        return lease

                    interruption = KeyboardInterrupt(
                        f"injected carrier-cleanup {boundary} interruption"
                    )
                    cleanup_failure = (
                        claude_linux.LinuxCredentialInspectionInconclusive(
                            "injected carrier cleanup failure"
                        )
                    )
                    if boundary.startswith("abandon-"):
                        interrupt_context = self._interrupt_cleanup_call_boundaries(
                            retain_helper,
                            target_lease=captured,
                            injections=[
                                (
                                    "abandon",
                                    boundary.removeprefix("abandon-"),
                                    [interruption],
                                )
                            ],
                            include_new_threads=True,
                        )
                    elif boundary.startswith("retain-"):
                        interrupt_context = self._interrupt_function_call_boundary(
                            coordinator_worker,
                            callee_name="_retain_lease",
                            window=boundary.removeprefix("retain-"),
                            target_lease=captured,
                            error=interruption,
                            include_new_threads=True,
                        )
                    else:
                        interrupt_context = self._interrupt_cleanup_call_boundaries(
                            retain_helper,
                            target_lease=captured,
                            injections=[
                                (
                                    "retention_snapshot",
                                    "entry",
                                    [interruption],
                                )
                            ],
                            include_new_threads=True,
                        )
                    try:
                        with (
                            mock.patch.object(
                                claude_linux,
                                "acquire_claude_refresh_lock",
                                side_effect=capture_host_lock,
                            ),
                            mock.patch.object(
                                claude_linux,
                                "_cleanup_staged_credential",
                                return_value=cleanup_failure,
                            ),
                            interrupt_context,
                            self.assertRaises(KeyboardInterrupt) as raised,
                        ):
                            with claude_linux.stage_claude_credentials(
                                source,
                                helper,
                                now=now,
                                refresh_lock_protocol=self.PROTOCOL,
                            ) as staged:
                                pass

                        self.assertIs(raised.exception, interruption)
                        self.assertEqual(len(captured), 1)
                        lease = captured[0]
                        heartbeat = lease._heartbeat_thread
                        self.assertIsNotNone(heartbeat)
                        assert heartbeat is not None
                        self.assertTrue(lease._deletion_prohibited)
                        self.assertFalse(heartbeat.is_alive())
                        self.assertTrue(all(path.is_dir() for path in lease.paths))
                        self._assert_refresh_lock_descriptors_closed(lease)
                        self.assertTrue(
                            getattr(
                                raised.exception,
                                "_codex_claude_refresh_lock_paths",
                                None,
                            )
                            or getattr(
                                raised.exception,
                                ("_codex_claude_refresh_lock_descriptor_bound"),
                                False,
                            )
                        )
                    finally:
                        for lease in captured:
                            self._dispose_refresh_lock_fixture(lease)
                        if staged is not None:
                            self.assertIsNone(
                                claude_linux._cleanup_staged_credential(staged)
                            )

    def test_unchanged_poll_reuses_host_lock_without_staged_lock(self) -> None:
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
                    self.assertEqual(
                        acquire_lock.call_args_list,
                        [
                            mock.call(
                                source.parent,
                                protocol=self.PROTOCOL,
                                owner=mock.ANY,
                                config_dir_fd=mock.ANY,
                                legacy_parent_dir_fd=mock.ANY,
                                require_explicit_context_release=True,
                            )
                        ],
                    )

            self.assertEqual(
                sum(
                    pathlib.Path(call.args[0]) == source.parent
                    for call in acquire_lock.call_args_list
                ),
                1,
            )
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

    def test_host_refresh_lock_precedes_source_read_and_spans_runtime(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            transaction_active = False
            source_read = False
            real_read = claude_linux._read_valid_credential
            staged_lease = mock.Mock(spec=["assert_held", "release"])

            def release_host_lease() -> None:
                nonlocal transaction_active
                self.assertTrue(transaction_active)
                transaction_active = False

            host_lease = self._CoordinatorLeaseFixture(
                release_callback=release_host_lease,
            )

            def acquire_refresh_lock(
                config_dir: os.PathLike[str] | str,
                **kwargs: object,
            ) -> mock.Mock:
                nonlocal transaction_active
                if pathlib.Path(config_dir) == source.parent:
                    self.assertFalse(transaction_active)
                    transaction_active = True
                    lease = host_lease
                else:
                    lease = staged_lease
                owner = kwargs["owner"]
                assert isinstance(
                    owner,
                    claude_refresh_lock.ClaudeRefreshLockOwner,
                )
                owner._publish(lease)
                return lease

            def read_credential(
                path: pathlib.Path,
                *args: object,
                **kwargs: object,
            ) -> tuple[bytearray, float, object]:
                nonlocal source_read
                if pathlib.Path(path) == source and not source_read:
                    self.assertTrue(
                        transaction_active,
                        "host refresh transaction must precede credential exposure",
                    )
                    source_read = True
                return real_read(path, *args, **kwargs)

            with (
                mock.patch.object(
                    claude_linux,
                    "acquire_claude_refresh_lock",
                    side_effect=acquire_refresh_lock,
                ) as acquire_lock,
                mock.patch.object(
                    claude_linux,
                    "_read_valid_credential",
                    side_effect=read_credential,
                ),
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ):
                    self.assertTrue(transaction_active)

            self.assertTrue(source_read)
            self.assertFalse(transaction_active)
            host_lease.release.assert_called_once_with()
            self.assertEqual(
                sum(
                    pathlib.Path(call.args[0]) == source.parent
                    for call in acquire_lock.call_args_list
                ),
                1,
            )

    def test_carrier_cleanup_failure_abandons_host_refresh_lock(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config_dir = root / "host-config"
            config_dir.mkdir(mode=0o700)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                config_dir / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            primary_lock = config_dir / self.PROTOCOL.primary_lock_name
            legacy_lock = root / "host-config.lock"
            real_acquire = claude_linux.acquire_claude_refresh_lock
            staged: claude_linux.StagedCredential | None = None

            class ObservedHostLease:
                def __init__(
                    self,
                    lease: claude_refresh_lock.ClaudeRefreshLockLease,
                ) -> None:
                    self._lease = lease
                    self.release_count = 0
                    self.abandon_results: list[
                        claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                    ] = []

                def __getattr__(self, name: str) -> object:
                    return getattr(self._lease, name)

                @property
                def _deletion_prohibited(self) -> bool:
                    return self._lease._deletion_prohibited

                @_deletion_prohibited.setter
                def _deletion_prohibited(self, value: bool) -> None:
                    self._lease._deletion_prohibited = value

                def assert_held(self) -> None:
                    self._lease.assert_held()

                def release(self) -> None:
                    self.release_count += 1
                    self._lease.release()

                def abandon(
                    self,
                    reason: str,
                ) -> claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive:
                    result = self._lease.abandon(reason)
                    self.abandon_results.append(result)
                    return result

            host_leases: list[ObservedHostLease] = []

            def acquire_refresh_lock(
                config_dir: os.PathLike[str] | str,
                **kwargs: object,
            ) -> claude_refresh_lock.ClaudeRefreshLockLease | ObservedHostLease:
                caller_owner = kwargs["owner"]
                assert isinstance(
                    caller_owner,
                    claude_refresh_lock.ClaudeRefreshLockOwner,
                )
                delegated_owner = claude_refresh_lock.ClaudeRefreshLockOwner()
                delegated_kwargs = dict(kwargs)
                delegated_kwargs["owner"] = delegated_owner
                lease = real_acquire(config_dir, **delegated_kwargs)
                delegated_owner.transfer(lease)
                if pathlib.Path(config_dir) == source.parent:
                    result = ObservedHostLease(lease)
                    host_leases.append(result)
                else:
                    result = lease
                caller_owner._publish(result)
                return result

            cleanup_failure = claude_linux.LinuxCredentialInspectionInconclusive(
                "injected carrier cleanup failure"
            )
            with (
                mock.patch.object(
                    claude_linux,
                    "acquire_claude_refresh_lock",
                    side_effect=acquire_refresh_lock,
                ),
                mock.patch.object(
                    claude_linux,
                    "_cleanup_staged_credential",
                    return_value=cleanup_failure,
                ),
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialInspectionInconclusive,
                    "injected carrier cleanup failure",
                ) as raised,
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ) as staged:
                    pass

            assert staged is not None
            self.assertEqual(len(host_leases), 1)
            host_lease = host_leases[0]
            self.assertEqual(host_lease.release_count, 0)
            self.assertEqual(len(host_lease.abandon_results), 1)
            abandonment_diagnostic = host_lease.abandon_results[0]
            self.assertIs(
                host_lease.abandon("terminal diagnostic must remain cached"),
                abandonment_diagnostic,
            )
            self.assertTrue(
                getattr(
                    raised.exception,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertNotIn(str(primary_lock), str(raised.exception))
            self.assertNotIn(str(legacy_lock), str(raised.exception))
            self.assertTrue(primary_lock.is_dir())
            self.assertTrue(legacy_lock.is_dir())
            self.assertTrue(staged.credential_path.is_file())

            self.assertIsNone(claude_linux._cleanup_staged_credential(staged))
            primary_lock.rmdir()
            legacy_lock.rmdir()

    def test_carrier_cleanup_control_flow_abandons_before_propagation(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config_dir = root / "host-config"
            config_dir.mkdir(mode=0o700)
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                config_dir / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            primary_lock = config_dir / self.PROTOCOL.primary_lock_name
            legacy_lock = root / "host-config.lock"
            real_acquire = claude_linux.acquire_claude_refresh_lock
            staged: claude_linux.StagedCredential | None = None

            class ObservedHostLease:
                def __init__(
                    self,
                    lease: claude_refresh_lock.ClaudeRefreshLockLease,
                ) -> None:
                    self._lease = lease
                    self.release_count = 0
                    self.abandon_results: list[
                        claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                    ] = []

                def __getattr__(self, name: str) -> object:
                    return getattr(self._lease, name)

                @property
                def _deletion_prohibited(self) -> bool:
                    return self._lease._deletion_prohibited

                @_deletion_prohibited.setter
                def _deletion_prohibited(self, value: bool) -> None:
                    self._lease._deletion_prohibited = value

                def assert_held(self) -> None:
                    self._lease.assert_held()

                def release(self) -> None:
                    self.release_count += 1
                    self._lease.release()

                def abandon(
                    self,
                    reason: str,
                ) -> claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive:
                    result = self._lease.abandon(reason)
                    self.abandon_results.append(result)
                    return result

            host_leases: list[ObservedHostLease] = []

            def acquire_refresh_lock(
                config_dir: os.PathLike[str] | str,
                **kwargs: object,
            ) -> claude_refresh_lock.ClaudeRefreshLockLease | ObservedHostLease:
                caller_owner = kwargs["owner"]
                assert isinstance(
                    caller_owner,
                    claude_refresh_lock.ClaudeRefreshLockOwner,
                )
                delegated_owner = claude_refresh_lock.ClaudeRefreshLockOwner()
                delegated_kwargs = dict(kwargs)
                delegated_kwargs["owner"] = delegated_owner
                lease = real_acquire(config_dir, **delegated_kwargs)
                delegated_owner.transfer(lease)
                if pathlib.Path(config_dir) == source.parent:
                    result = ObservedHostLease(lease)
                    host_leases.append(result)
                else:
                    result = lease
                caller_owner._publish(result)
                return result

            cleanup_signal = claude_linux.ForwardedSignal(signal.SIGTERM)

            def interrupt_cleanup(
                _staged: claude_linux.StagedCredential,
            ) -> BaseException | None:
                raise cleanup_signal

            with (
                mock.patch.object(
                    claude_linux,
                    "acquire_claude_refresh_lock",
                    side_effect=acquire_refresh_lock,
                ),
                mock.patch.object(
                    claude_linux._StagedCredentialWatcher,
                    "scrub",
                    side_effect=OSError("injected payload scrub failure"),
                ),
                mock.patch.object(
                    claude_linux,
                    "_cleanup_staged_credential",
                    side_effect=interrupt_cleanup,
                ),
                self.assertRaises(claude_linux.ForwardedSignal) as raised,
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ) as staged:
                    pass

            assert staged is not None
            self.assertIs(raised.exception, cleanup_signal)
            self.assertEqual(raised.exception.signum, signal.SIGTERM)
            self.assertIn(
                "refresh-lock cleanup is inconclusive",
                raised.exception.detail or "",
            )
            self.assertEqual(len(host_leases), 1)
            host_lease = host_leases[0]
            self.assertEqual(host_lease.release_count, 0)
            self.assertEqual(len(host_lease.abandon_results), 1)
            abandonment_diagnostic = host_lease.abandon_results[0]
            self.assertIs(
                host_lease.abandon("terminal diagnostic must remain cached"),
                abandonment_diagnostic,
            )
            self.assertTrue(primary_lock.is_dir())
            self.assertTrue(legacy_lock.is_dir())
            self.assertTrue(staged.credential_path.is_file())

            self.assertIsNone(claude_linux._cleanup_staged_credential(staged))
            primary_lock.rmdir()
            legacy_lock.rmdir()

    def test_parallel_reviewers_read_source_after_host_lock_handoff(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            first_helper = root / "first-helper"
            second_helper = root / "second-helper"
            first_helper.mkdir(mode=0o700)
            second_helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
                access_token=self.SYNTH_ACCESS_EXPIRED,
                refresh_token=self.SYNTH_REFRESH_A,
            )
            first_staged = threading.Event()
            allow_first_writeback = threading.Event()
            first_cleanup_started = threading.Event()
            allow_first_cleanup = threading.Event()
            first_cleanup_finished = threading.Event()
            first_host_released = threading.Event()
            first_finished = threading.Event()
            second_contended = threading.Event()
            second_retried_during_cleanup = threading.Event()
            allow_second_retry = threading.Event()
            second_host_acquired = threading.Event()
            second_source_read = threading.Event()
            second_finished = threading.Event()
            thread_errors: list[BaseException] = []
            second_refresh_tokens: list[str] = []
            host_acquirers: list[str] = []
            real_acquire = claude_linux.acquire_claude_refresh_lock
            real_mkdir = claude_refresh_lock.os.mkdir
            real_read = claude_linux._read_valid_credential
            real_cleanup = claude_linux._cleanup_staged_credential

            class ObservedFirstLease:
                def __init__(
                    self,
                    lease: claude_refresh_lock.ClaudeRefreshLockLease,
                ) -> None:
                    self._lease = lease

                def __getattr__(self, name: str) -> object:
                    return getattr(self._lease, name)

                @property
                def _deletion_prohibited(self) -> bool:
                    return self._lease._deletion_prohibited

                @_deletion_prohibited.setter
                def _deletion_prohibited(self, value: bool) -> None:
                    self._lease._deletion_prohibited = value

                def assert_held(self) -> None:
                    self._lease.assert_held()

                def release(self) -> None:
                    self._lease.release()
                    first_host_released.set()

                def _release(self, *, skip_abandoned: bool) -> None:
                    self._lease._release(skip_abandoned=skip_abandoned)
                    first_host_released.set()

                def abandon(
                    self,
                    reason: str,
                ) -> claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive:
                    return self._lease.abandon(reason)

            def observe_mkdir(
                path: os.PathLike[str] | str,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> None:
                try:
                    real_mkdir(path, mode, dir_fd=dir_fd)
                except FileExistsError:
                    if (
                        threading.current_thread().name == "second-reviewer"
                        and os.fspath(path) == self.PROTOCOL.primary_lock_name
                    ):
                        if not second_contended.is_set():
                            second_contended.set()
                            if not allow_second_retry.wait(timeout=3.0):
                                raise TimeoutError(
                                    "second reviewer retry fixture timed out"
                                )
                        elif (
                            first_cleanup_started.is_set()
                            and not first_cleanup_finished.is_set()
                        ):
                            second_retried_during_cleanup.set()
                    raise

            def observe_acquire(
                config_dir: os.PathLike[str] | str,
                **kwargs: object,
            ) -> claude_refresh_lock.ClaudeRefreshLockLease | ObservedFirstLease:
                caller_owner = kwargs["owner"]
                assert isinstance(
                    caller_owner,
                    claude_refresh_lock.ClaudeRefreshLockOwner,
                )
                delegated_owner = claude_refresh_lock.ClaudeRefreshLockOwner()
                delegated_kwargs = dict(kwargs)
                delegated_kwargs["owner"] = delegated_owner
                lease = real_acquire(config_dir, **delegated_kwargs)
                delegated_owner.transfer(lease)
                result: (
                    claude_refresh_lock.ClaudeRefreshLockLease | ObservedFirstLease
                ) = lease
                if pathlib.Path(config_dir) == source.parent:
                    thread_name = threading.current_thread().name
                    host_acquirers.append(thread_name)
                    if thread_name == "first-reviewer":
                        result = ObservedFirstLease(lease)
                    elif thread_name == "second-reviewer":
                        second_host_acquired.set()
                caller_owner._publish(result)
                return result

            def observe_read(
                path: pathlib.Path,
                *args: object,
                **kwargs: object,
            ) -> tuple[bytearray, float, object]:
                result = real_read(path, *args, **kwargs)
                if (
                    pathlib.Path(path) == source
                    and threading.current_thread().name == "second-reviewer"
                    and not second_source_read.is_set()
                ):
                    self.assertTrue(second_host_acquired.is_set())
                    self.assertTrue(first_host_released.is_set())
                    payload = json.loads(result[0])
                    second_refresh_tokens.append(
                        payload["claudeAiOauth"]["refreshToken"]
                    )
                    second_source_read.set()
                return result

            def observe_cleanup(
                staged: claude_linux.StagedCredential,
            ) -> BaseException | None:
                if threading.current_thread().name != "first-reviewer":
                    return real_cleanup(staged)
                first_cleanup_started.set()
                self.assertFalse(
                    first_host_released.is_set(),
                    "host transaction lock must span carrier cleanup",
                )
                if not allow_first_cleanup.wait(timeout=3.0):
                    raise TimeoutError("first reviewer cleanup fixture timed out")
                result = real_cleanup(staged)
                first_cleanup_finished.set()
                return result

            def run_first_reviewer() -> None:
                try:
                    with claude_linux.stage_claude_credentials(
                        source,
                        first_helper,
                        now=now,
                        refresh_lock_protocol=self.PROTOCOL,
                    ) as staged:
                        first_staged.set()
                        if not allow_first_writeback.wait(timeout=3.0):
                            raise TimeoutError(
                                "first reviewer writeback fixture timed out"
                            )
                        refreshed = self._credential(
                            staged.config_dir / "refresh-b.json",
                            expires_at_ms=(now + 7200) * 1000,
                            access_token=self.SYNTH_ACCESS_A,
                            refresh_token=self.SYNTH_REFRESH_B,
                        )
                        refreshed.replace(staged.credential_path)
                except BaseException as error:
                    thread_errors.append(error)
                finally:
                    first_finished.set()

            def run_second_reviewer() -> None:
                try:
                    with claude_linux.stage_claude_credentials(
                        source,
                        second_helper,
                        now=now,
                        refresh_lock_protocol=self.PROTOCOL,
                    ):
                        pass
                except BaseException as error:
                    thread_errors.append(error)
                finally:
                    second_finished.set()

            first_thread = threading.Thread(
                target=run_first_reviewer,
                name="first-reviewer",
                daemon=True,
            )
            second_thread = threading.Thread(
                target=run_second_reviewer,
                name="second-reviewer",
                daemon=True,
            )
            with (
                mock.patch.object(
                    claude_linux,
                    "block_forwarded_signals",
                    side_effect=self._publish_test_signal_mask,
                ),
                mock.patch.object(
                    claude_linux,
                    "restore_signal_mask",
                ),
                mock.patch.object(
                    claude_linux,
                    "acquire_claude_refresh_lock",
                    side_effect=observe_acquire,
                ),
                mock.patch.object(
                    claude_refresh_lock.os,
                    "mkdir",
                    side_effect=observe_mkdir,
                ),
                mock.patch.object(
                    claude_linux,
                    "_read_valid_credential",
                    side_effect=observe_read,
                ),
                mock.patch.object(
                    claude_linux,
                    "_cleanup_staged_credential",
                    side_effect=observe_cleanup,
                ),
            ):
                try:
                    first_thread.start()
                    self.assertTrue(first_staged.wait(timeout=3.0))
                    second_thread.start()
                    self.assertTrue(second_contended.wait(timeout=3.0))
                    self.assertFalse(second_host_acquired.is_set())
                    self.assertFalse(second_source_read.is_set())
                    allow_first_writeback.set()
                    self.assertTrue(first_cleanup_started.wait(timeout=3.0))
                    self.assertFalse(first_host_released.is_set())
                    self.assertFalse(second_host_acquired.is_set())
                    self.assertFalse(second_source_read.is_set())
                    allow_second_retry.set()
                    self.assertTrue(second_retried_during_cleanup.wait(timeout=3.0))
                    self.assertFalse(first_host_released.is_set())
                    self.assertFalse(second_host_acquired.is_set())
                    self.assertFalse(second_source_read.is_set())
                    allow_first_cleanup.set()
                    self.assertTrue(first_cleanup_finished.wait(timeout=3.0))
                    self.assertTrue(first_host_released.wait(timeout=3.0))
                    self.assertTrue(first_finished.wait(timeout=3.0))
                    self.assertTrue(second_source_read.wait(timeout=3.0))
                    self.assertTrue(second_finished.wait(timeout=3.0))
                finally:
                    allow_first_writeback.set()
                    allow_first_cleanup.set()
                    allow_second_retry.set()
                    first_thread.join(timeout=3.0)
                    second_thread.join(timeout=3.0)

            self.assertFalse(first_thread.is_alive())
            self.assertFalse(second_thread.is_alive())
            self.assertTrue(first_cleanup_finished.is_set())
            self.assertTrue(second_retried_during_cleanup.is_set())
            self.assertEqual(thread_errors, [])
            self.assertEqual(
                host_acquirers,
                ["first-reviewer", "second-reviewer"],
            )
            self.assertEqual(second_refresh_tokens, [self.SYNTH_REFRESH_B])
            host = json.loads(source.read_text(encoding="utf-8"))
            self.assertEqual(
                host["claudeAiOauth"]["refreshToken"],
                self.SYNTH_REFRESH_B,
            )
            self.assertEqual(list(first_helper.iterdir()), [])
            self.assertEqual(list(second_helper.iterdir()), [])

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

    def test_timeout_abandons_lease_before_admitted_background_writeback(
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
                self.assertTrue(
                    getattr(
                        raised.exception,
                        "_codex_claude_refresh_lock_descriptor_bound",
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
                        self.SYNTH_REFRESH_A,
                    )
                    worker_failure = watchers[0].worker_failure()
                    self.assertIsInstance(
                        worker_failure,
                        claude_linux.LinuxCredentialInspectionInconclusive,
                    )
                    self.assertIn("refresh lock changed", str(worker_failure))
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
                    "import os, pathlib, signal, sys, threading",
                    "sys.path.insert(0, sys.argv[1])",
                    "from review_runtime import claude_linux, claude_refresh_lock",
                    "source = pathlib.Path(sys.argv[2])",
                    "helper = pathlib.Path(sys.argv[3])",
                    "started = threading.Event()",
                    "release_drain = threading.Event()",
                    "real_retain_anchor = claude_linux._StagedCredentialWatcher.retain_source_anchor_after_timeout",
                    "signal_sent = False",
                    "def forward_signal(signum, _frame):",
                    "    raise claude_linux.ForwardedSignal(signal.Signals(signum))",
                    "signal.signal(signal.SIGTERM, forward_signal)",
                    "def block_drain(self, *, final):",
                    "    if final:",
                    "        return",
                    "    started.set()",
                    "    release_drain.wait()",
                    "def signal_during_handoff(self):",
                    "    global signal_sent",
                    "    real_retain_anchor(self)",
                    "    if not signal_sent:",
                    "        signal_sent = True",
                    "        os.kill(os.getpid(), signal.SIGTERM)",
                    "claude_linux.STAGED_CREDENTIAL_POLL_SECONDS = 0.01",
                    "claude_linux.STAGED_CREDENTIAL_JOIN_TIMEOUT_SECONDS = 0.01",
                    "claude_linux._StagedCredentialWatcher._drain = block_drain",
                    "claude_linux._StagedCredentialWatcher.retain_source_anchor_after_timeout = signal_during_handoff",
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
                self.SYNTH_REFRESH_A,
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

    def _assert_interrupted_start_before_started_publication_retains_carrier(
        self,
        *,
        confirmation_error: BaseException | None,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            forwarded = claude_linux.ForwardedSignal(signal.SIGTERM)
            native_thread_entered = threading.Event()
            allow_bootstrap = threading.Event()
            watchers: list[claude_linux._StagedCredentialWatcher] = []
            source_anchor_descriptors: list[int] = []
            staged_credentials: list[claude_linux.StagedCredential] = []
            host_leases: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
            real_publish = (
                claude_linux._HostRefreshLockCleanupCoordinator.publish_watcher
            )
            real_acquire = claude_linux.acquire_claude_refresh_lock

            def acquire_refresh_lock(
                config_path: os.PathLike[str] | str,
                **kwargs: object,
            ) -> claude_refresh_lock.ClaudeRefreshLockLease:
                lease = real_acquire(config_path, **kwargs)
                if pathlib.Path(config_path) == source.parent:
                    host_leases.append(lease)
                return lease

            def publish_watcher(
                coordinator: (claude_linux._HostRefreshLockCleanupCoordinator),
                staged: claude_linux.StagedCredential,
                watcher: claude_linux._StagedCredentialWatcher,
            ) -> None:
                real_publish(coordinator, staged, watcher)
                watchers.append(watcher)
                source_anchor_descriptors.append(watcher._source_anchor.descriptor)
                staged_credentials.append(staged)
                real_bootstrap = watcher._thread._bootstrap_inner
                real_started_wait = watcher._thread._started.wait
                started_wait_calls = 0

                def delayed_bootstrap() -> None:
                    native_thread_entered.set()
                    allow_bootstrap.wait(timeout=2.0)
                    real_bootstrap()

                def interrupt_first_started_wait(
                    timeout: float | None = None,
                ) -> bool:
                    nonlocal started_wait_calls
                    started_wait_calls += 1
                    if started_wait_calls == 1:
                        if not native_thread_entered.wait(timeout=2.0):
                            raise AssertionError("native watcher thread did not start")
                        raise forwarded
                    if started_wait_calls == 2 and confirmation_error is not None:
                        raise confirmation_error
                    return real_started_wait(timeout)

                watcher._thread._bootstrap_inner = delayed_bootstrap
                watcher._thread._started.wait = interrupt_first_started_wait

            try:
                with (
                    mock.patch.object(
                        claude_linux,
                        "STAGED_CREDENTIAL_JOIN_TIMEOUT_SECONDS",
                        0.01,
                    ),
                    mock.patch.object(
                        claude_linux,
                        "acquire_claude_refresh_lock",
                        side_effect=acquire_refresh_lock,
                    ),
                    mock.patch.object(
                        claude_linux._HostRefreshLockCleanupCoordinator,
                        "publish_watcher",
                        autospec=True,
                        side_effect=publish_watcher,
                    ),
                    self.assertRaises(claude_linux.ForwardedSignal) as caught,
                ):
                    with claude_linux.stage_claude_credentials(
                        source,
                        helper,
                        now=now,
                        refresh_lock_protocol=self.PROTOCOL,
                    ):
                        self.fail("an interrupted watcher start must not yield")

                self.assertIs(caught.exception, forwarded)
                self.assertEqual(len(watchers), 1)
                watcher = watchers[0]
                self.assertTrue(watcher._stop.is_set())
                self.assertTrue(watcher._source_anchor.detached_to_watcher)
                self.assertFalse(watcher._source_anchor_cleanup_reached)
                self.assertEqual(len(source_anchor_descriptors), 1)
                os.fstat(source_anchor_descriptors[0])
                self.assertEqual(len(host_leases), 1)
                host_lease = host_leases[0]
                snapshot = host_lease.retention_snapshot()
                self.assertTrue(snapshot.terminal)
                self.assertFalse(host_lease.released)
                self._assert_assignment_interrupt_retained_lock(host_lease)
                self.assertIsNotNone(snapshot.diagnostic)
                self.assertEqual(
                    getattr(
                        snapshot.diagnostic,
                        "_codex_claude_refresh_lock_paths",
                        (),
                    ),
                    (),
                )
                self.assertTrue(
                    getattr(
                        snapshot.diagnostic,
                        "_codex_claude_refresh_lock_descriptor_bound",
                        False,
                    )
                )
                self._assert_retained_recovery_carrier(
                    error=caught.exception,
                    staged=staged_credentials[0],
                    helper=helper,
                    expected_refresh_token=self.SYNTH_REFRESH_A,
                )
            finally:
                allow_bootstrap.set()
                for watcher in watchers:
                    watcher.request_stop()
                    watcher._thread._started.wait(timeout=1.0)
                    if watcher._thread._started.is_set():
                        watcher._thread.join(timeout=1.0)
                for lease in host_leases:
                    if lease.retention_snapshot().terminal:
                        continue
                    lease._deletion_prohibited = True
                    lease._heartbeat_stop.set()
                    try:
                        lease.abandon("test cleanup after interrupted watcher startup")
                    except claude_refresh_lock.ClaudeRefreshLockError:
                        pass

            self.assertEqual(len(watchers), 1)
            self.assertFalse(watchers[0]._thread.is_alive())
            self.assertTrue(watchers[0]._source_anchor_cleanup_reached)
            self.assertEqual(len(source_anchor_descriptors), 1)
            with self.assertRaises(OSError) as raised:
                os.fstat(source_anchor_descriptors[0])
            self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_interrupted_start_before_started_publication_retains_carrier(
        self,
    ) -> None:
        self._assert_interrupted_start_before_started_publication_retains_carrier(
            confirmation_error=None,
        )

    def test_interrupted_start_confirmation_error_retains_carrier(
        self,
    ) -> None:
        self._assert_interrupted_start_before_started_publication_retains_carrier(
            confirmation_error=OSError("cannot confirm watcher startup"),
        )

    def test_unknown_watcher_start_confirms_then_joins(self) -> None:
        watcher = object.__new__(claude_linux._StagedCredentialWatcher)
        watcher._stop = threading.Event()
        watcher._background_writeback_state_lock = threading.Lock()
        watcher._background_writeback_admission_open = True
        watcher._background_writeback_in_flight = False
        watcher._background_writeback_was_in_flight_at_stop = False
        watcher._start_state_lock = threading.Lock()
        watcher._start_state = claude_linux._StagedCredentialWatcherStartState.UNKNOWN
        watcher._stop_deadline = None
        watcher._thread = threading.Thread(
            target=watcher._stop.wait,
            name="delayed-staged-credential-watcher",
            daemon=True,
        )
        native_thread_entered = threading.Event()
        allow_bootstrap = threading.Event()
        real_bootstrap = watcher._thread._bootstrap_inner

        def delayed_bootstrap() -> None:
            native_thread_entered.set()
            allow_bootstrap.wait(timeout=2.0)
            real_bootstrap()

        watcher._thread._bootstrap_inner = delayed_bootstrap
        launcher = threading.Thread(
            target=watcher._thread.start,
            name="delayed-watcher-native-launcher",
            daemon=True,
        )
        launcher.start()
        self.assertTrue(native_thread_entered.wait(timeout=1.0))
        self.assertIsNone(watcher.request_stop())
        allow_bootstrap.set()

        self.assertTrue(watcher.wait_until_stopped())
        launcher.join(timeout=1.0)
        self.assertFalse(launcher.is_alive())
        self.assertFalse(watcher._thread.is_alive())
        self.assertEqual(
            watcher.start_state(),
            claude_linux._StagedCredentialWatcherStartState.CONFIRMED,
        )

    def test_watcher_request_stop_bounds_persistent_state_failures(
        self,
    ) -> None:
        expected_attempts = 2

        class EventuallyAvailableLock:
            def __init__(self, message: str) -> None:
                self.message = message
                self.enter_calls = 0

            def __enter__(self) -> object:
                self.enter_calls += 1
                if self.enter_calls <= expected_attempts:
                    raise OSError(self.message)
                return self

            def __exit__(
                self,
                _exception_type: object,
                _exception: object,
                _traceback: object,
            ) -> bool:
                return False

        class EventuallyAvailableStop:
            def __init__(self) -> None:
                self.is_set_calls = 0
                self.set_calls = 0

            def is_set(self) -> bool:
                self.is_set_calls += 1
                return False

            def set(self) -> None:
                self.set_calls += 1
                if self.set_calls <= expected_attempts:
                    raise OSError("injected persistent stop-state failure")

        watcher = object.__new__(claude_linux._StagedCredentialWatcher)
        background_lock = EventuallyAvailableLock(
            "injected persistent writeback-state failure"
        )
        start_lock = EventuallyAvailableLock(
            "injected persistent stop-deadline failure"
        )
        stop = EventuallyAvailableStop()
        watcher._background_writeback_state_lock = background_lock  # type: ignore[assignment]
        watcher._background_writeback_admission_open = True
        watcher._background_writeback_in_flight = False
        watcher._background_writeback_was_in_flight_at_stop = False
        watcher._stop = stop  # type: ignore[assignment]
        watcher._start_state_lock = start_lock  # type: ignore[assignment]
        watcher._stop_deadline = None

        error = watcher.request_stop()

        self.assertIsInstance(error, OSError)
        self.assertEqual(background_lock.enter_calls, expected_attempts)
        self.assertEqual(stop.is_set_calls, 0)
        self.assertEqual(stop.set_calls, expected_attempts)
        self.assertEqual(start_lock.enter_calls, expected_attempts)
        self.assertTrue(watcher._background_writeback_admission_open)
        self.assertIsNone(watcher._stop_deadline)

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

        def acquire_refresh_lock(
            _config_dir: os.PathLike[str] | str,
            **kwargs: object,
        ) -> mock.Mock:
            owner = kwargs["owner"]
            assert isinstance(
                owner,
                claude_refresh_lock.ClaudeRefreshLockOwner,
            )
            owner._publish(refresh_lock)
            return refresh_lock

        with (
            mock.patch.object(
                claude_linux,
                "acquire_claude_refresh_lock",
                side_effect=acquire_refresh_lock,
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

    def test_cleanup_coordinator_start_failure_has_terminal_cancel(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(time.time() - 60) * 1000,
            )
            source_anchor = claude_linux._open_credential_directory_anchor(
                source,
                owner_uid=os.getuid(),
            )
            coordinator = claude_linux._HostRefreshLockCleanupCoordinator(source_anchor)
            start_failure = OSError(
                errno.EAGAIN,
                "injected cleanup coordinator start failure",
            )
            cancel_errors: list[BaseException] = []

            def cancel_without_lease() -> None:
                try:
                    coordinator.cancel_without_lease()
                except BaseException as error:
                    cancel_errors.append(error)

            cancel_thread = threading.Thread(
                target=cancel_without_lease,
                daemon=True,
            )
            try:
                with (
                    mock.patch.object(
                        coordinator._thread,
                        "start",
                        side_effect=start_failure,
                    ),
                    self.assertRaises(OSError) as raised,
                ):
                    coordinator.start()
                self.assertIs(raised.exception, start_failure)

                cancel_thread.start()
                cancel_thread.join(timeout=0.5)
                self.assertFalse(
                    cancel_thread.is_alive(),
                    "pre-start coordinator failure left cancel nonterminal",
                )
                self.assertEqual(cancel_errors, [])
                self.assertTrue(coordinator._terminal.is_set())
                self.assertIsNone(coordinator.owner.lease)
            finally:
                if cancel_thread.is_alive():
                    coordinator._terminal.set()
                    cancel_thread.join(timeout=1.0)
                source_anchor.close_if_owned()

    def test_start_failure_retries_gate_close_and_adopts_published_lease(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=True) as (
            _root,
            _source,
            _anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            start_failure = OSError(
                errno.EAGAIN,
                "injected cleanup coordinator start failure",
            )
            gate_control = KeyboardInterrupt(
                "injected publication-gate close interruption"
            )
            real_close_publication = coordinator.owner.close_publication
            close_calls = 0

            def interrupt_gate_close_once() -> (
                claude_refresh_lock.ClaudeRefreshLockLease | None
            ):
                nonlocal close_calls
                close_calls += 1
                if close_calls == 1:
                    raise gate_control
                return real_close_publication()

            with (
                mock.patch.object(
                    coordinator._thread,
                    "start",
                    side_effect=start_failure,
                ),
                mock.patch.object(
                    coordinator.owner,
                    "close_publication",
                    side_effect=interrupt_gate_close_once,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                coordinator.start()

            self.assertIs(raised.exception, gate_control)
            self.assertGreaterEqual(close_calls, 2)
            self.assertIs(
                coordinator._phase_snapshot(),
                claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
            )
            self.assertIs(coordinator.owner.lease, lease)
            self.assertIs(
                coordinator._decision,
                claude_linux._HostRefreshLockCleanupDecision.CANCEL,
            )
            self.assertTrue(coordinator._source_terminal)
            self.assertTrue(lease.retention_snapshot().terminal)
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            heartbeat.join(timeout=1.0)
            self.assertFalse(heartbeat.is_alive())

    def test_start_failure_claims_created_phase_before_worker_entry(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=False) as (
            _root,
            _source,
            _anchor,
            coordinator,
            _lease,
        ):
            start_failure = OSError(
                errno.EIO,
                "injected Thread.start handoff failure",
            )
            allow_worker_entry = threading.Event()
            worker_entry_attempted = threading.Event()
            worker_entry_results: list[bool] = []
            real_thread_start = coordinator._thread.start
            real_claim_worker_entry = coordinator._claim_worker_entry
            real_finish_without_worker = coordinator._finish_without_worker

            def delayed_worker_entry() -> bool:
                allow_worker_entry.wait(timeout=1.0)
                claimed = real_claim_worker_entry()
                worker_entry_results.append(claimed)
                worker_entry_attempted.set()
                return claimed

            def start_then_fail() -> None:
                real_thread_start()
                raise start_failure

            def release_worker_before_finish(
                *args: object,
            ) -> tuple[BaseException, ...]:
                allow_worker_entry.set()
                self.assertTrue(worker_entry_attempted.wait(timeout=0.5))
                return real_finish_without_worker(*args)

            with (
                mock.patch.object(
                    coordinator,
                    "_claim_worker_entry",
                    side_effect=delayed_worker_entry,
                ),
                mock.patch.object(
                    coordinator._thread,
                    "start",
                    side_effect=start_then_fail,
                ),
                mock.patch.object(
                    coordinator,
                    "_finish_without_worker",
                    side_effect=release_worker_before_finish,
                ),
                self.assertRaises(OSError) as raised,
            ):
                coordinator.start()

            self.assertIs(raised.exception, start_failure)
            allow_worker_entry.set()
            coordinator._thread.join(timeout=1.0)
            self.assertFalse(coordinator._thread.is_alive())
            self.assertEqual(worker_entry_results, [False])
            self.assertIs(
                coordinator._phase_snapshot(),
                claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
            )

    def test_late_thread_start_failure_delivers_worker_control_flow(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=False) as (
            _root,
            _source,
            _anchor,
            coordinator,
            _lease,
        ):
            start_failure = OSError(
                errno.EIO,
                "injected late Thread.start failure",
            )
            worker_control = KeyboardInterrupt("injected worker decision interruption")
            real_thread_start = coordinator._thread.start
            real_wait_for_decision = coordinator._wait_for_decision
            decision_wait_calls = 0

            def start_then_fail() -> None:
                real_thread_start()
                self.assertTrue(coordinator._worker_entered.wait(timeout=0.5))
                raise start_failure

            def interrupt_then_wait() -> claude_linux._HostRefreshLockCleanupDecision:
                nonlocal decision_wait_calls
                decision_wait_calls += 1
                if decision_wait_calls == 1:
                    raise worker_control
                return real_wait_for_decision()

            with (
                mock.patch.object(
                    coordinator._thread,
                    "start",
                    side_effect=start_then_fail,
                ),
                mock.patch.object(
                    coordinator,
                    "_wait_for_decision",
                    side_effect=interrupt_then_wait,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                coordinator.start()

            self.assertIs(raised.exception, worker_control)
            self.assertIs(
                coordinator._phase_snapshot(),
                claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
            )
            coordinator.cancel_without_lease()

    def test_unmasked_cleanup_cancels_start_failed_coordinator_without_lease(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(time.time() - 60) * 1000,
            )
            source_anchor = claude_linux._open_credential_directory_anchor(
                source,
                owner_uid=os.getuid(),
            )
            coordinator = claude_linux._HostRefreshLockCleanupCoordinator(source_anchor)
            start_failure = OSError(
                errno.EAGAIN,
                "injected cleanup coordinator start failure",
            )
            mask_failure = OSError(
                errno.EPERM,
                "injected forwarded-signal mask failure",
            )
            try:
                with (
                    mock.patch.object(
                        coordinator._thread,
                        "start",
                        side_effect=start_failure,
                    ),
                    self.assertRaises(OSError) as raised,
                ):
                    coordinator.start()
                self.assertIs(raised.exception, start_failure)

                with (
                    mock.patch.object(
                        coordinator,
                        "cancel_without_lease",
                        wraps=coordinator.cancel_without_lease,
                    ) as cancel,
                    mock.patch.object(
                        coordinator,
                        "retain",
                        wraps=coordinator.retain,
                    ) as retain,
                ):
                    result = claude_linux._retain_unmasked_credential_cleanup(
                        mask_errors=[mask_failure],
                        staged=None,
                        carrier_root=None,
                        watcher=None,
                        watcher_started=False,
                        host_refresh_lock_owner=coordinator.owner,
                        host_refresh_lock=None,
                        host_refresh_lock_coordinator=coordinator,
                    )

                self.assertIsInstance(
                    result,
                    claude_linux.LinuxCredentialInspectionInconclusive,
                )
                self.assertTrue(
                    any(
                        node is mask_failure
                        for node in self._explicit_cause_nodes(result)
                    )
                )
                cancel.assert_called_once_with()
                retain.assert_not_called()
                self.assertIs(
                    coordinator._decision,
                    claude_linux._HostRefreshLockCleanupDecision.CANCEL,
                )
                self.assertTrue(coordinator._terminal.is_set())
                self.assertIsNone(coordinator.owner.lease)
            finally:
                source_anchor.close_if_owned()

    def test_cleanup_coordinator_settles_live_heartbeat_as_retained_residue(
        self,
    ) -> None:
        class RetainedHeartbeat:
            def __init__(self, allow_exit: threading.Event) -> None:
                self.allow_exit = allow_exit

            def join(self, timeout: float | None = None) -> None:
                self.allow_exit.wait(min(timeout or 0.0, 0.005))

            def is_alive(self) -> bool:
                return not self.allow_exit.is_set()

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(time.time() - 60) * 1000,
            )
            source_anchor = claude_linux._open_credential_directory_anchor(
                source,
                owner_uid=os.getuid(),
            )
            coordinator = claude_linux._HostRefreshLockCleanupCoordinator(source_anchor)
            lease: claude_refresh_lock.ClaudeRefreshLockLease | None = None
            real_heartbeat: threading.Thread | None = None
            allow_exit = threading.Event()
            retain_errors: list[BaseException] = []
            retain_failures: list[BaseException] = []

            def retain() -> None:
                try:
                    retain_errors.extend(
                        coordinator.retain(reason="injected live heartbeat retention")
                    )
                except BaseException as error:
                    retain_failures.append(error)

            retain_thread = threading.Thread(
                target=retain,
                daemon=True,
            )
            try:
                coordinator._thread.start()
                self.assertTrue(coordinator._ready.wait(timeout=1.0))
                lease = claude_linux.acquire_claude_refresh_lock(
                    source.parent,
                    protocol=self.PROTOCOL,
                    owner=coordinator.owner,
                    timeout_seconds=0,
                    config_dir_fd=source_anchor.descriptor,
                    legacy_parent_dir_fd=(source_anchor.legacy_parent_descriptor),
                    require_explicit_context_release=True,
                )
                coordinator.owner.transfer(lease)
                real_heartbeat = lease._heartbeat_thread
                assert real_heartbeat is not None
                lease._heartbeat_stop.set()
                real_heartbeat.join(timeout=1.0)
                self.assertFalse(real_heartbeat.is_alive())
                lease._heartbeat_thread = RetainedHeartbeat(  # type: ignore[assignment]
                    allow_exit
                )
                known_descriptors = {
                    *(lock.descriptor for lock in lease._locks),
                    lease._legacy_parent_anchor.descriptor,
                    lease._config_anchor.descriptor,
                }

                with (
                    mock.patch.object(
                        lease,
                        "abandon",
                        wraps=lease.abandon,
                    ) as abandon,
                    mock.patch.object(
                        lease,
                        "release",
                        wraps=lease.release,
                    ) as release,
                ):
                    retain_thread.start()
                    retain_thread.join(timeout=0.5)

                self.assertFalse(
                    retain_thread.is_alive(),
                    "live heartbeat left coordinator retention unbounded",
                )
                self.assertFalse(coordinator._thread.is_alive())
                self.assertEqual(retain_failures, [])
                self.assertNotEqual(retain_errors, [])
                self.assertEqual(abandon.call_count, 2)
                self.assertEqual(release.call_count, 2)
                snapshot = lease.retention_snapshot()
                self.assertTrue(snapshot.terminal)
                self.assertFalse(snapshot.verified_closed)
                self.assertIs(
                    snapshot.diagnostic,
                    lease._descriptor_bound_cleanup_fallback,
                )
                assert snapshot.diagnostic is not None
                self.assertTrue(
                    getattr(
                        snapshot.diagnostic,
                        "_codex_claude_refresh_lock_descriptor_bound",
                        False,
                    )
                )
                self.assertFalse(lease.released)
                self.assertTrue(all(path.is_dir() for path in lease.paths))
                self.assertTrue(
                    known_descriptors.issubset(lease._abandonment_descriptors_residue)
                )
                self.assertEqual(lease._abandonment_descriptors_pending, [])
                self.assertEqual(
                    lease._abandonment_descriptors_unconfirmed,
                    set(),
                )
                for descriptor in known_descriptors:
                    os.fstat(descriptor)
                with self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive
                ) as raised:
                    lease.release()
                self.assertIs(
                    raised.exception,
                    lease._descriptor_bound_cleanup_fallback,
                )
                self.assertTrue(all(path.is_dir() for path in lease.paths))
            finally:
                allow_exit.set()
                if retain_thread.ident is not None:
                    retain_thread.join(timeout=1.0)
                if coordinator._thread.ident is not None:
                    coordinator._terminal.set()
                    coordinator._thread.join(timeout=1.0)
                if lease is not None:
                    lease._heartbeat_thread = real_heartbeat
                    self._dispose_refresh_lock_fixture(lease)
                source_anchor.close_if_owned()

    def test_cleanup_coordinator_bounds_persistent_watcher_failures(
        self,
    ) -> None:
        class EventuallyAvailableWatcher:
            def __init__(
                self,
                source_anchor: claude_linux._CredentialDirectoryAnchor,
                allow_source_handoff: threading.Event,
                source_handoff_attempted: threading.Event,
                repeated_failures_observed: threading.Event,
            ) -> None:
                self.source_anchor = source_anchor
                self.allow_source_handoff = allow_source_handoff
                self.source_handoff_attempted = source_handoff_attempted
                self.repeated_failures_observed = repeated_failures_observed
                self.request_stop_calls = 0
                self.wait_calls = 0
                self.retain_anchor_calls = 0

            def may_have_started(self) -> bool:
                return True

            def request_stop(self) -> None:
                self.request_stop_calls += 1

            def wait_until_stopped(self) -> bool:
                self.wait_calls += 1
                return False

            def retain_source_anchor_after_timeout(self) -> None:
                self.retain_anchor_calls += 1
                self.source_handoff_attempted.set()
                if self.retain_anchor_calls >= (
                    claude_linux.CREDENTIAL_CLEANUP_STATE_MAX_ATTEMPTS
                ):
                    self.repeated_failures_observed.set()
                if not self.allow_source_handoff.is_set():
                    raise OSError(
                        "injected persistent source-handoff failure "
                        f"{self.retain_anchor_calls}"
                    )
                self.source_anchor.detach_to_watcher()

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(time.time() - 60) * 1000,
            )
            carrier = root / "retained-carrier"
            config_dir = carrier / "config"
            config_dir.mkdir(parents=True)
            staged = claude_linux.StagedCredential(
                carrier_root=carrier,
                config_dir=config_dir,
                credential_path=config_dir / ".credentials.json",
                expires_at_ms=(time.time() + 3600) * 1000,
            )
            source_anchor = claude_linux._open_credential_directory_anchor(
                source,
                owner_uid=os.getuid(),
            )
            source_descriptors = source_anchor._descriptors
            source_descriptor = source_anchor.descriptor
            allow_source_handoff = threading.Event()
            source_handoff_attempted = threading.Event()
            repeated_failures_observed = threading.Event()
            watcher = EventuallyAvailableWatcher(
                source_anchor,
                allow_source_handoff,
                source_handoff_attempted,
                repeated_failures_observed,
            )
            coordinator = claude_linux._HostRefreshLockCleanupCoordinator(source_anchor)
            lease: claude_refresh_lock.ClaudeRefreshLockLease | None = None
            retain_errors: list[BaseException] = []
            retain_failures: list[BaseException] = []

            def retain() -> None:
                try:
                    retain_errors.extend(
                        coordinator.retain(
                            reason="injected persistent watcher retention"
                        )
                    )
                except BaseException as error:
                    retain_failures.append(error)

            retain_thread = threading.Thread(target=retain, daemon=True)
            try:
                coordinator._thread.start()
                self.assertTrue(coordinator._ready.wait(timeout=1.0))
                lease = claude_linux.acquire_claude_refresh_lock(
                    source.parent,
                    protocol=self.PROTOCOL,
                    owner=coordinator.owner,
                    timeout_seconds=0,
                    config_dir_fd=source_anchor.descriptor,
                    legacy_parent_dir_fd=(source_anchor.legacy_parent_descriptor),
                    require_explicit_context_release=True,
                )
                coordinator.owner.transfer(lease)
                coordinator.publish_watcher(staged, watcher)  # type: ignore[arg-type]

                retain_thread.start()
                self.assertTrue(source_handoff_attempted.wait(timeout=0.5))
                self.assertTrue(repeated_failures_observed.wait(timeout=1.0))
                retain_thread.join(timeout=1.0)

                self.assertFalse(retain_thread.is_alive())
                self.assertEqual(retain_failures, [])
                self.assertNotEqual(retain_errors, [])
                self.assertTrue(coordinator._source_terminal)
                self.assertFalse(source_anchor.detached_to_watcher)
                self.assertIs(
                    source_anchor.disposition,
                    claude_linux._CredentialDirectoryAnchorDisposition.DESCRIPTOR_RESIDUE,
                )
                diagnostic = source_anchor.descriptor_residue_diagnostic
                self.assertIsNotNone(diagnostic)
                assert diagnostic is not None
                self.assertTrue(any(error is diagnostic for error in retain_errors))
                self.assertTrue(
                    getattr(
                        diagnostic,
                        "_codex_claude_refresh_lock_descriptor_bound",
                        False,
                    )
                )
                os.fstat(source_descriptor)
                self.assertTrue(carrier.is_dir())
                self.assertIs(
                    coordinator._phase_snapshot(),
                    claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
                )
                snapshot = lease.retention_snapshot()
                self.assertTrue(snapshot.terminal)
                self.assertFalse(lease.released)
                self.assertTrue(all(path.is_dir() for path in lease.paths))
                handoff_errors = [
                    error
                    for error in coordinator._errors
                    if str(error).startswith(
                        "injected persistent source-handoff failure"
                    )
                ]
                self.assertLessEqual(
                    len(handoff_errors),
                    claude_linux.CREDENTIAL_CLEANUP_STATE_MAX_ATTEMPTS,
                )
                self.assertEqual(
                    sum(
                        "additional source-anchor handoff failures were "
                        "suppressed" in str(error)
                        for error in coordinator._errors
                    ),
                    1,
                )
            finally:
                if retain_thread.ident is not None:
                    retain_thread.join(timeout=1.0)
                if coordinator._thread.ident is not None:
                    coordinator._terminal.set()
                    coordinator._thread.join(timeout=1.0)
                if lease is not None:
                    self._dispose_refresh_lock_fixture(lease)
                if source_anchor.disposition is (
                    claude_linux._CredentialDirectoryAnchorDisposition.DESCRIPTOR_RESIDUE
                ):
                    for descriptor in reversed(source_descriptors):
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass
                    with source_anchor._state_lock:
                        source_anchor._disposition = (
                            claude_linux._CredentialDirectoryAnchorDisposition.CLOSED
                        )
                        source_anchor._descriptor_residue_diagnostic = None
                else:
                    source_anchor.close_if_detached()
                    source_anchor.close_if_owned()

    def test_stopped_watcher_transfer_interruption_requires_close_proof(
        self,
    ) -> None:
        class InterruptedStoppedWatcher:
            def __init__(
                self,
                source_anchor: claude_linux._CredentialDirectoryAnchor,
                interruption: BaseException,
            ) -> None:
                self.source_anchor = source_anchor
                self.interruption = interruption
                self.retain_anchor_calls = 0

            def may_have_started(self) -> bool:
                return True

            def request_stop(self) -> None:
                return None

            def wait_until_stopped(self) -> bool:
                return True

            def retain_source_anchor_after_timeout(self) -> None:
                self.retain_anchor_calls += 1
                self.source_anchor.detach_to_watcher()
                if self.retain_anchor_calls == 1:
                    raise self.interruption
                self.source_anchor.close_if_detached()

        with self._host_cleanup_coordinator_fixture(with_lease=True) as (
            root,
            _source,
            source_anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            carrier = root / "retained-carrier"
            config_dir = carrier / "config"
            config_dir.mkdir(parents=True)
            staged = claude_linux.StagedCredential(
                carrier_root=carrier,
                config_dir=config_dir,
                credential_path=config_dir / ".credentials.json",
                expires_at_ms=(time.time() + 3600) * 1000,
            )
            control_flow = KeyboardInterrupt(
                "injected stopped-watcher transfer interruption"
            )
            watcher = InterruptedStoppedWatcher(source_anchor, control_flow)
            coordinator.publish_watcher(staged, watcher)  # type: ignore[arg-type]

            with self.assertRaises(KeyboardInterrupt) as raised:
                coordinator._thread.start()
                coordinator.retain(
                    reason="injected stopped-watcher transfer interruption"
                )

            self.assertIs(raised.exception, control_flow)
            self.assertGreaterEqual(watcher.retain_anchor_calls, 2)
            self.assertIs(
                source_anchor.disposition,
                claude_linux._CredentialDirectoryAnchorDisposition.CLOSED,
            )
            self.assertTrue(coordinator._source_terminal)
            self.assertIs(
                coordinator._phase_snapshot(),
                claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
            )
            self.assertTrue(lease.retention_snapshot().terminal)

    def test_cleanup_coordinator_retains_unknown_source_close_as_residue(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(
            with_lease=True,
            allow_source_residue=True,
        ) as (
            _root,
            _source,
            source_anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            target_descriptor = source_anchor._descriptors[-1]
            target_close_calls = 0
            real_close = claude_linux.os.close

            def close_then_report_unknown(descriptor: int) -> None:
                nonlocal target_close_calls
                real_close(descriptor)
                if descriptor == target_descriptor:
                    target_close_calls += 1
                    raise OSError("injected coordinator source-close outcome unknown")

            with mock.patch.object(
                claude_linux.os,
                "close",
                side_effect=close_then_report_unknown,
            ):
                coordinator._thread.start()
                errors = coordinator.retain(
                    reason="injected source-close descriptor residue"
                )

                self.assertIs(
                    source_anchor.disposition,
                    claude_linux._CredentialDirectoryAnchorDisposition.DESCRIPTOR_RESIDUE,
                )
                diagnostic = source_anchor.descriptor_residue_diagnostic
                self.assertIsNotNone(diagnostic)
                assert diagnostic is not None
                self.assertTrue(any(error is diagnostic for error in errors))
                self.assertTrue(
                    getattr(
                        diagnostic,
                        "_codex_claude_refresh_lock_descriptor_bound",
                        False,
                    )
                )
                self.assertFalse(
                    hasattr(diagnostic, "_codex_claude_refresh_lock_paths")
                )
                self.assertTrue(coordinator._source_terminal)
                self.assertIs(
                    coordinator._phase_snapshot(),
                    claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
                )
                with self.assertRaises(
                    claude_linux.LinuxCredentialInspectionInconclusive
                ) as repeated:
                    source_anchor.close_if_detached()
                self.assertIs(repeated.exception, diagnostic)
                self.assertEqual(target_close_calls, 1)

    def test_unmasked_cleanup_bounds_persistent_legacy_transitions(
        self,
    ) -> None:
        expected_attempts = claude_linux.CREDENTIAL_CLEANUP_STATE_MAX_ATTEMPTS

        class EventuallyAvailableWatcher:
            def __init__(self) -> None:
                self.request_stop_calls = 0
                self.wait_calls = 0
                self.retain_anchor_calls = 0

            def may_have_started(self) -> bool:
                return True

            def request_stop(self) -> None:
                self.request_stop_calls += 1
                if self.request_stop_calls <= expected_attempts:
                    raise OSError("injected persistent watcher stop failure")

            def wait_until_stopped(self) -> bool:
                self.wait_calls += 1
                if self.wait_calls <= expected_attempts:
                    raise OSError("injected persistent watcher wait failure")
                return True

            def retain_source_anchor_after_timeout(self) -> None:
                self.retain_anchor_calls += 1
                if self.retain_anchor_calls <= expected_attempts:
                    raise OSError("injected persistent source-retention failure")

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            carrier = root / "retained-carrier"
            config_dir = carrier / "config"
            config_dir.mkdir(parents=True)
            staged = claude_linux.StagedCredential(
                carrier_root=carrier,
                config_dir=config_dir,
                credential_path=config_dir / ".credentials.json",
                expires_at_ms=(time.time() + 3600) * 1000,
            )
            lock_config = root / "host-config"
            lock_config.mkdir(mode=0o700)
            owner = claude_refresh_lock.ClaudeRefreshLockOwner()
            lease = claude_linux.acquire_claude_refresh_lock(
                lock_config,
                protocol=self.PROTOCOL,
                owner=owner,
            )
            owner.transfer(lease)
            watcher = EventuallyAvailableWatcher()
            mask_failure = OSError(
                errno.EPERM,
                "injected forwarded-signal mask failure",
            )
            mask_errors: list[BaseException] = [mask_failure]
            abandon_calls = 0
            release_calls = 0
            real_abandon = claude_linux._abandon_owned_claude_refresh_lock
            real_release = lease.release

            def abandon_after_bound(
                *args: object,
                **kwargs: object,
            ) -> claude_linux._ClaudeRefreshLockCleanupResult:
                nonlocal abandon_calls
                abandon_calls += 1
                if abandon_calls <= expected_attempts:
                    raise OSError("injected persistent abandonment-boundary failure")
                return real_abandon(*args, **kwargs)

            def release_after_bound() -> None:
                nonlocal release_calls
                release_calls += 1
                if release_calls <= expected_attempts:
                    raise OSError("injected persistent release-boundary failure")
                real_release()

            try:
                with (
                    mock.patch.object(
                        claude_linux,
                        "_abandon_owned_claude_refresh_lock",
                        side_effect=abandon_after_bound,
                    ),
                    mock.patch.object(
                        lease,
                        "release",
                        side_effect=release_after_bound,
                    ),
                ):
                    result = claude_linux._retain_unmasked_credential_cleanup(
                        mask_errors=mask_errors,
                        staged=staged,
                        carrier_root=carrier,
                        watcher=watcher,  # type: ignore[arg-type]
                        watcher_started=True,
                        host_refresh_lock_owner=owner,
                        host_refresh_lock=lease,
                        host_refresh_lock_coordinator=None,
                    )

                self.assertIsInstance(
                    result,
                    claude_linux.LinuxCredentialInspectionInconclusive,
                )
                self.assertIn(
                    mask_failure,
                    self._explicit_cause_nodes(result),
                )
                self.assertEqual(
                    watcher.request_stop_calls,
                    expected_attempts,
                )
                self.assertEqual(watcher.wait_calls, expected_attempts)
                self.assertEqual(
                    watcher.retain_anchor_calls,
                    expected_attempts,
                )
                self.assertEqual(abandon_calls, expected_attempts)
                self.assertEqual(release_calls, expected_attempts)
                snapshot = lease.retention_snapshot()
                self.assertTrue(snapshot.terminal)
                self.assertFalse(snapshot.verified_closed)
                self.assertIs(
                    snapshot.diagnostic,
                    lease._descriptor_bound_cleanup_fallback,
                )
                self.assertTrue(
                    getattr(
                        result,
                        "_codex_claude_refresh_lock_descriptor_bound",
                        False,
                    )
                )
                self.assertEqual(
                    getattr(
                        result,
                        "_codex_claude_retained_credential_carrier",
                    ),
                    str(carrier),
                )
                self.assertTrue(carrier.is_dir())
                self.assertFalse(lease.released)
                self.assertTrue(all(path.is_dir() for path in lease.paths))
                for descriptor in {
                    *(lock.descriptor for lock in lease._locks),
                    lease._legacy_parent_anchor.descriptor,
                    lease._config_anchor.descriptor,
                }:
                    os.fstat(descriptor)
            finally:
                self._dispose_refresh_lock_fixture(lease)

    def test_cleanup_coordinator_retries_decision_wait_before_acquire(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(time.time() - 60) * 1000,
            )
            source_anchor = claude_linux._open_credential_directory_anchor(
                source,
                owner_uid=os.getuid(),
            )
            coordinator = claude_linux._HostRefreshLockCleanupCoordinator(source_anchor)
            interruption = KeyboardInterrupt(
                "injected cleanup coordinator decision-wait interruption"
            )
            real_wait_for_decision = coordinator._wait_for_decision
            wait_calls = 0
            signal_mask_owner = claude_linux.ForwardedSignalMaskOwner()
            lease: claude_refresh_lock.ClaudeRefreshLockLease | None = None
            retained_errors: list[BaseException] = []
            retain_failures: list[BaseException] = []

            def wait_for_decision() -> claude_linux._HostRefreshLockCleanupDecision:
                nonlocal wait_calls
                wait_calls += 1
                if wait_calls == 1:
                    raise interruption
                return real_wait_for_decision()

            def retain() -> None:
                try:
                    retained_errors.extend(
                        coordinator.retain(reason="injected coordinator retention")
                    )
                except BaseException as error:
                    retain_failures.append(error)

            retain_thread = threading.Thread(
                target=retain,
                daemon=True,
            )
            try:
                claude_linux.block_forwarded_signals(
                    signal_mask_owner=signal_mask_owner,
                )
                with mock.patch.object(
                    coordinator,
                    "_wait_for_decision",
                    side_effect=wait_for_decision,
                ):
                    coordinator.start()
                    lease = claude_linux.acquire_claude_refresh_lock(
                        source.parent,
                        protocol=self.PROTOCOL,
                        owner=coordinator.owner,
                        config_dir_fd=source_anchor.descriptor,
                        legacy_parent_dir_fd=(source_anchor.legacy_parent_descriptor),
                        require_explicit_context_release=True,
                    )
                    coordinator.owner.transfer(lease)
                    claude_linux._restore_forwarded_signal_mask_owner(
                        signal_mask_owner,
                        None,
                    )

                    retain_thread.start()
                    retain_thread.join(timeout=0.5)
                    self.assertFalse(
                        retain_thread.is_alive(),
                        "decision-wait interruption killed the cleanup worker",
                    )
                self.assertEqual(retain_failures, [interruption])
                self.assertEqual(retained_errors, [])
                repeated_errors = coordinator.retain(
                    reason="injected coordinator retention"
                )
                self.assertNotIn(interruption, repeated_errors)
                self.assertGreaterEqual(wait_calls, 2)
                assert lease is not None
                self._assert_assignment_interrupt_retained_lock(lease)
                coordinator._thread.join(timeout=1.0)
                self.assertFalse(coordinator._thread.is_alive())
            finally:
                if signal_mask_owner.active:
                    claude_linux._restore_forwarded_signal_mask_owner(
                        signal_mask_owner,
                        None,
                    )
                if retain_thread.is_alive():
                    coordinator._terminal.set()
                    retain_thread.join(timeout=1.0)
                if lease is not None:
                    self._dispose_refresh_lock_fixture(lease)
                source_anchor.close_if_owned()

    def test_cleanup_coordinator_bounds_persistent_decision_wait_failures(
        self,
    ) -> None:
        expected_attempts = claude_linux.CREDENTIAL_CLEANUP_STATE_MAX_ATTEMPTS

        for decision in (
            claude_linux._HostRefreshLockCleanupDecision.RETAIN,
            claude_linux._HostRefreshLockCleanupDecision.CANCEL,
        ):
            with self.subTest(decision=decision.name):
                with tempfile.TemporaryDirectory() as temporary:
                    root = pathlib.Path(temporary).resolve()
                    source = self._credential(
                        root / ".credentials.json",
                        expires_at_ms=(time.time() - 60) * 1000,
                    )
                    source_anchor = claude_linux._open_credential_directory_anchor(
                        source,
                        owner_uid=os.getuid(),
                    )
                    coordinator = claude_linux._HostRefreshLockCleanupCoordinator(
                        source_anchor
                    )
                    lease: claude_refresh_lock.ClaudeRefreshLockLease | None = None
                    wait_calls = 0
                    wait_exhausted = threading.Event()
                    real_wait_for_decision = coordinator._wait_for_decision

                    def wait_after_bound() -> (
                        claude_linux._HostRefreshLockCleanupDecision
                    ):
                        nonlocal wait_calls
                        wait_calls += 1
                        if wait_calls <= expected_attempts:
                            if wait_calls == expected_attempts:
                                wait_exhausted.set()
                            raise OSError("injected persistent decision-wait failure")
                        return real_wait_for_decision()

                    try:
                        with mock.patch.object(
                            coordinator,
                            "_wait_for_decision",
                            side_effect=wait_after_bound,
                        ):
                            coordinator._thread.start()
                            self.assertTrue(wait_exhausted.wait(timeout=0.5))
                            if (
                                decision
                                is claude_linux._HostRefreshLockCleanupDecision.RETAIN
                            ):
                                lease = claude_linux.acquire_claude_refresh_lock(
                                    source.parent,
                                    protocol=self.PROTOCOL,
                                    owner=coordinator.owner,
                                    timeout_seconds=0,
                                    config_dir_fd=(source_anchor.descriptor),
                                    legacy_parent_dir_fd=(
                                        source_anchor.legacy_parent_descriptor
                                    ),
                                    require_explicit_context_release=True,
                                )
                                coordinator.owner.transfer(lease)
                                coordinator._decide(
                                    decision,
                                    retention_reason=(
                                        "main published retention after "
                                        "decision-wait exhaustion"
                                    ),
                                )
                            else:
                                coordinator._decide(decision)
                            coordinator._thread.join(timeout=0.5)

                        self.assertFalse(
                            coordinator._thread.is_alive(),
                            "persistent decision-wait failures left the "
                            "cleanup coordinator nonterminal",
                        )
                        self.assertTrue(coordinator._terminal.is_set())
                        self.assertEqual(wait_calls, expected_attempts)
                        self.assertIs(coordinator._decision, decision)
                        self.assertTrue(
                            any(
                                "decision" in str(error)
                                for error in coordinator._errors
                            )
                        )
                        if lease is not None:
                            snapshot = lease.retention_snapshot()
                            self.assertTrue(snapshot.terminal)
                            self.assertFalse(lease.released)
                            self.assertTrue(all(path.is_dir() for path in lease.paths))
                        else:
                            self.assertIsNone(coordinator.owner.lease)
                    finally:
                        if coordinator._thread.ident is not None:
                            coordinator._terminal.set()
                            coordinator._thread.join(timeout=1.0)
                        if lease is not None:
                            self._dispose_refresh_lock_fixture(lease)
                        source_anchor.close_if_owned()

    def test_cleanup_coordinator_uses_sticky_decision_after_event_failures(
        self,
    ) -> None:
        expected_attempts = claude_linux.CREDENTIAL_CLEANUP_STATE_MAX_ATTEMPTS
        with self._host_cleanup_coordinator_fixture(with_lease=True) as (
            _root,
            _source,
            _anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            decision_set_calls = 0
            decision_interruptions: list[BaseException] = [
                KeyboardInterrupt("injected first sticky-decision event interruption"),
                KeyboardInterrupt("injected second sticky-decision event interruption"),
            ]

            def interrupt_decision_event() -> None:
                nonlocal decision_set_calls
                decision_set_calls += 1
                if decision_set_calls <= expected_attempts:
                    raise decision_interruptions[decision_set_calls - 1]

            coordinator._thread.start()
            with (
                mock.patch.object(
                    coordinator._condition,
                    "notify_all",
                    side_effect=interrupt_decision_event,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                coordinator.retain(reason="injected sticky-decision retention")

            self.assertEqual(decision_set_calls, expected_attempts)
            self.assertIs(raised.exception, decision_interruptions[0])
            self.assertTrue(
                getattr(
                    raised.exception,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            retained_errors = coordinator.retain(
                reason="injected sticky-decision retention"
            )
            self.assertEqual(
                sum(isinstance(error, KeyboardInterrupt) for error in retained_errors),
                0,
            )
            self.assertFalse(coordinator._thread.is_alive())
            self.assertTrue(coordinator._terminal.is_set())
            snapshot = lease.retention_snapshot()
            self.assertTrue(snapshot.terminal)
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in lease.paths))

    def test_cleanup_coordinator_terminal_wait_rejects_dead_worker(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=True) as (
            _root,
            _source,
            _anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            real_terminal_set = coordinator._terminal.set
            terminal_set_calls = 0
            retain_errors: list[BaseException] = []
            terminal_interruptions: list[BaseException] = [
                KeyboardInterrupt("injected first terminal-publication interruption"),
                KeyboardInterrupt("injected second terminal-publication interruption"),
            ]

            def interrupt_terminal_publish() -> None:
                nonlocal terminal_set_calls
                terminal_set_calls += 1
                if (
                    terminal_set_calls
                    <= claude_linux.CREDENTIAL_CLEANUP_STATE_MAX_ATTEMPTS
                ):
                    raise terminal_interruptions[terminal_set_calls - 1]
                real_terminal_set()

            def retain() -> None:
                try:
                    coordinator.retain(reason="injected terminal-publication retention")
                except BaseException as error:
                    retain_errors.append(error)

            retain_thread = threading.Thread(target=retain, daemon=True)
            wait_was_stuck = False
            try:
                with mock.patch.object(
                    coordinator._terminal,
                    "set",
                    side_effect=interrupt_terminal_publish,
                ):
                    coordinator._thread.start()
                    retain_thread.start()
                    retain_thread.join(timeout=0.5)
                    wait_was_stuck = retain_thread.is_alive()

                if wait_was_stuck:
                    real_terminal_set()
                    retain_thread.join(timeout=1.0)

                self.assertFalse(
                    wait_was_stuck,
                    "dead cleanup worker left terminal wait unbounded",
                )
                self.assertFalse(retain_thread.is_alive())
                self.assertFalse(coordinator._thread.is_alive())
                self.assertEqual(
                    terminal_set_calls,
                    claude_linux.CREDENTIAL_CLEANUP_STATE_MAX_ATTEMPTS,
                )
                self.assertEqual(len(retain_errors), 1)
                self.assertIs(retain_errors[0], terminal_interruptions[0])
                self.assertTrue(
                    getattr(
                        retain_errors[0],
                        "_codex_claude_refresh_lock_descriptor_bound",
                        False,
                    )
                )
                self.assertIn(
                    str(terminal_interruptions[1]),
                    self._visible_explicit_cause_text(retain_errors[0]),
                )
                self.assertTrue(coordinator._source_terminal)
                snapshot = lease.retention_snapshot()
                self.assertTrue(snapshot.terminal)
                self.assertFalse(lease.released)
                self.assertTrue(all(path.is_dir() for path in lease.paths))
            finally:
                real_terminal_set()
                if retain_thread.ident is not None:
                    retain_thread.join(timeout=1.0)

    def test_cancel_surfaces_worker_decision_control_flow_once(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=False) as (
            _root,
            _source,
            _anchor,
            coordinator,
            _lease,
        ):
            control_flow = KeyboardInterrupt(
                "injected worker decision-wait interruption"
            )
            real_wait_for_decision = coordinator._wait_for_decision
            wait_calls = 0

            def interrupt_then_wait() -> claude_linux._HostRefreshLockCleanupDecision:
                nonlocal wait_calls
                wait_calls += 1
                if wait_calls == 1:
                    raise control_flow
                return real_wait_for_decision()

            with (
                mock.patch.object(
                    coordinator,
                    "_wait_for_decision",
                    side_effect=interrupt_then_wait,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                coordinator._thread.start()
                coordinator.cancel_without_lease()

            self.assertIs(raised.exception, control_flow)
            self.assertTrue(coordinator._terminal.is_set())
            self.assertFalse(coordinator._thread.is_alive())
            self.assertIsNone(coordinator.owner.lease)
            self.assertIs(
                coordinator._decision,
                claude_linux._HostRefreshLockCleanupDecision.CANCEL,
            )

            coordinator.cancel_without_lease()

    def test_dead_worker_takeover_is_single_and_terminal_before_control_flow(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=True) as (
            _root,
            _source,
            _anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            waiter_control = KeyboardInterrupt(
                "injected dead-worker waiter interruption"
            )
            cleanup_entered = threading.Event()
            allow_cleanup = threading.Event()
            secondary_claim_attempted = threading.Event()
            cleanup_calls = 0
            caught: dict[str, BaseException] = {}
            claim_results: dict[
                str, tuple[bool, claude_refresh_lock.ClaudeRefreshLockLease | None]
            ] = {}
            real_fail_closed = coordinator._fail_closed_worker
            real_claim = coordinator._claim_synchronous_cleanup

            def delayed_fail_closed() -> None:
                nonlocal cleanup_calls
                cleanup_calls += 1
                cleanup_entered.set()
                allow_cleanup.wait(timeout=1.0)
                real_fail_closed()

            def observe_claim() -> tuple[
                bool, claude_refresh_lock.ClaudeRefreshLockLease | None
            ]:
                result = real_claim()
                name = threading.current_thread().name
                claim_results[name] = result
                if name == "secondary":
                    secondary_claim_attempted.set()
                return result

            def wait(name: str, local_errors: list[BaseException]) -> None:
                try:
                    coordinator._wait_until_terminal(local_errors=local_errors)
                except BaseException as error:
                    caught[name] = error

            with coordinator._state_lock:
                coordinator._phase = (
                    claude_linux._HostRefreshLockCleanupPhase.WORKER_ENTERED
                )
            primary_waiter = threading.Thread(
                target=wait,
                args=("primary", [waiter_control]),
                name="primary",
                daemon=True,
            )
            secondary_waiter = threading.Thread(
                target=wait,
                args=("secondary", []),
                name="secondary",
                daemon=True,
            )
            try:
                with (
                    mock.patch.object(
                        coordinator,
                        "_fail_closed_worker",
                        side_effect=delayed_fail_closed,
                    ),
                    mock.patch.object(
                        coordinator,
                        "_claim_synchronous_cleanup",
                        side_effect=observe_claim,
                    ),
                ):
                    primary_waiter.start()
                    self.assertTrue(cleanup_entered.wait(timeout=0.5))
                    secondary_waiter.start()
                    self.assertTrue(secondary_claim_attempted.wait(timeout=0.5))
                    self.assertTrue(secondary_waiter.is_alive())
                    self.assertEqual(cleanup_calls, 1)
                    allow_cleanup.set()
                    primary_waiter.join(timeout=1.0)
                    secondary_waiter.join(timeout=1.0)
            finally:
                allow_cleanup.set()
                primary_waiter.join(timeout=1.0)
                if secondary_waiter.ident is not None:
                    secondary_waiter.join(timeout=1.0)

            self.assertFalse(primary_waiter.is_alive())
            self.assertFalse(secondary_waiter.is_alive())
            self.assertEqual(set(caught), {"primary"})
            self.assertIs(caught["primary"], waiter_control)
            self.assertEqual(cleanup_calls, 1)
            self.assertTrue(claim_results["primary"][0])
            self.assertFalse(claim_results["secondary"][0])
            self.assertIs(
                coordinator._phase_snapshot(),
                claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
            )
            self.assertTrue(coordinator._source_terminal)
            self.assertTrue(lease.retention_snapshot().terminal)
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            heartbeat.join(timeout=1.0)
            self.assertFalse(heartbeat.is_alive())

    def test_terminal_wait_bounds_unavailable_and_failed_liveness_probes(
        self,
    ) -> None:
        expected_attempts = claude_linux.CREDENTIAL_CLEANUP_STATE_MAX_ATTEMPTS
        for worker_dead, expected_probe_calls in (
            (True, 1),
            (False, expected_attempts + 1),
        ):
            with self.subTest(worker_dead=worker_dead):
                with self._host_cleanup_coordinator_fixture(with_lease=False) as (
                    _root,
                    _source,
                    _anchor,
                    coordinator,
                    _lease,
                ):
                    probe_error = OSError("injected persistent worker-liveness failure")
                    probe_calls = 0

                    def fail_liveness_until_gate() -> bool:
                        nonlocal probe_calls
                        probe_calls += 1
                        if worker_dead:
                            return False
                        if probe_calls <= expected_attempts:
                            raise probe_error
                        return False

                    with (
                        mock.patch.object(
                            coordinator._terminal,
                            "wait",
                            return_value=False,
                        ),
                        mock.patch.object(
                            coordinator._thread,
                            "is_alive",
                            side_effect=fail_liveness_until_gate,
                        ),
                    ):
                        errors = coordinator._wait_until_terminal()

                    self.assertEqual(probe_calls, expected_probe_calls)
                    self.assertLessEqual(
                        coordinator._errors.count(probe_error),
                        expected_attempts,
                    )
                    self.assertIs(
                        coordinator._phase_snapshot(),
                        claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
                    )
                    self.assertTrue(errors)
                    self.assertTrue(
                        any("source descriptor" in str(error) for error in errors)
                    )
                    if worker_dead:
                        self.assertNotIn(probe_error, errors)
                    else:
                        self.assertIn(probe_error, errors)

    def test_dead_worker_takeover_never_replays_normal_release(self) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=True) as (
            _root,
            _source,
            _anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            with coordinator._state_lock:
                coordinator._phase = (
                    claude_linux._HostRefreshLockCleanupPhase.WORKER_ENTERED
                )

            result = coordinator.release_after_proven_cleanup()

            self.assertIsNotNone(result.error)
            self.assertTrue(result.terminal)
            self.assertIs(
                coordinator._decision,
                claude_linux._HostRefreshLockCleanupDecision.NORMAL_RELEASE,
            )
            self.assertIs(
                coordinator._phase_snapshot(),
                claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
            )
            self.assertTrue(coordinator._source_terminal)
            self.assertTrue(lease.retention_snapshot().terminal)
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            heartbeat.join(timeout=1.0)
            self.assertFalse(heartbeat.is_alive())

    def test_dead_worker_takeover_bounds_unprovable_lease_terminal(self) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=True) as (
            _root,
            _source,
            _anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            limit = claude_linux.CREDENTIAL_CLEANUP_STATE_MAX_ATTEMPTS
            snapshot_attempts = 0
            settlement_attempts = 0
            results: list[claude_linux._ClaudeRefreshLockCleanupResult] = []
            errors: list[BaseException] = []
            real_retention_snapshot = lease.retention_snapshot
            real_settle_descriptor_bound = lease._settle_descriptor_bound_retention

            def fail_snapshot_with_escape_hatch() -> (
                claude_refresh_lock.ClaudeRefreshLockRetentionSnapshot
            ):
                nonlocal snapshot_attempts
                snapshot_attempts += 1
                if snapshot_attempts <= limit:
                    raise OSError(
                        f"injected persistent terminal snapshot {snapshot_attempts}"
                    )
                return dataclasses.replace(
                    real_retention_snapshot(),
                    terminal=False,
                )

            def fail_settlement_with_escape_hatch(reason: str) -> BaseException:
                nonlocal settlement_attempts
                settlement_attempts += 1
                if settlement_attempts <= limit:
                    raise OSError(
                        "injected persistent descriptor settlement failure "
                        f"{settlement_attempts}"
                    )
                return real_settle_descriptor_bound(reason)

            def release() -> None:
                try:
                    results.append(coordinator.release_after_proven_cleanup())
                except BaseException as error:
                    errors.append(error)

            def retain_source_without_settling_lease() -> None:
                coordinator._retaining = True
                coordinator._retention_reason = (
                    "injected persistent terminal-proof failure"
                )
                coordinator._retain_source_anchor()

            with coordinator._state_lock:
                coordinator._phase = (
                    claude_linux._HostRefreshLockCleanupPhase.WORKER_ENTERED
                )
            release_thread = threading.Thread(target=release, daemon=True)
            with (
                mock.patch.object(
                    lease,
                    "retention_snapshot",
                    side_effect=fail_snapshot_with_escape_hatch,
                ),
                mock.patch.object(
                    lease,
                    "_settle_descriptor_bound_retention",
                    side_effect=fail_settlement_with_escape_hatch,
                ),
                mock.patch.object(
                    coordinator,
                    "_fail_closed_worker",
                    side_effect=retain_source_without_settling_lease,
                ),
                mock.patch.object(
                    coordinator,
                    "_finalize_worker_retention",
                    return_value=None,
                ),
                mock.patch.object(claude_linux.time, "sleep", return_value=None),
                mock.patch.object(lease, "_release", wraps=lease._release) as release,
            ):
                release_thread.start()
                release_thread.join(timeout=1.0)
                release.assert_not_called()

            self.assertFalse(release_thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(len(results), 1)
            self.assertFalse(results[0].terminal)
            self.assertIsNotNone(results[0].error)
            assert results[0].error is not None
            self.assertTrue(
                getattr(
                    results[0].error,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertEqual(snapshot_attempts, limit)
            self.assertEqual(settlement_attempts, limit)
            self.assertIs(
                coordinator._phase_snapshot(),
                claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
            )
            self.assertFalse(coordinator._synchronous_cleanup_claimed)
            self.assertFalse(lease.retention_snapshot().terminal)
            self.assertTrue(all(path.is_dir() for path in lease.paths))
            descriptors = {
                *(lock.descriptor for lock in lease._locks),
                lease._legacy_parent_anchor.descriptor,
                lease._config_anchor.descriptor,
            }
            for descriptor in descriptors:
                os.fstat(descriptor)

    def test_terminal_proof_accepts_successful_descriptor_settlement_without_snapshot_reread(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=True) as (
            _root,
            _source,
            _anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            real_settle = lease._settle_descriptor_bound_retention
            with (
                mock.patch.object(
                    lease,
                    "retention_snapshot",
                    side_effect=OSError("injected unavailable terminal snapshot"),
                ) as snapshot,
                mock.patch.object(
                    lease,
                    "_settle_descriptor_bound_retention",
                    wraps=real_settle,
                ) as settle,
                mock.patch.object(claude_linux.time, "sleep", return_value=None),
            ):
                terminal_proof = coordinator._wait_for_cleanup_terminal_proof(
                    lease,
                    retry_scope="fixture",
                )

            self.assertTrue(terminal_proof.terminal)
            self.assertIsNotNone(terminal_proof.diagnostic)
            self.assertEqual(snapshot.call_count, 1)
            self.assertEqual(settle.call_count, 1)
            retention = lease.retention_snapshot()
            self.assertTrue(retention.terminal)
            self.assertFalse(retention.verified_closed)
            self.assertTrue(all(path.is_dir() for path in lease.paths))

    def test_release_uses_cached_descriptor_settlement_without_snapshot_reread(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=True) as (
            _root,
            _source,
            _anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            real_settle = lease._settle_descriptor_bound_retention

            def retain_source_without_settling_lease() -> None:
                coordinator._retaining = True
                coordinator._retention_reason = "injected cached terminal proof"
                coordinator._retain_source_anchor()

            with coordinator._state_lock:
                coordinator._phase = (
                    claude_linux._HostRefreshLockCleanupPhase.WORKER_ENTERED
                )
            with (
                mock.patch.object(
                    lease,
                    "retention_snapshot",
                    side_effect=OSError("injected unavailable terminal snapshot"),
                ) as snapshot,
                mock.patch.object(
                    lease,
                    "_settle_descriptor_bound_retention",
                    wraps=real_settle,
                ) as settle,
                mock.patch.object(
                    coordinator,
                    "_fail_closed_worker",
                    side_effect=retain_source_without_settling_lease,
                ),
                mock.patch.object(
                    coordinator,
                    "_finalize_worker_retention",
                    return_value=None,
                ),
                mock.patch.object(claude_linux.time, "sleep", return_value=None),
            ):
                result = coordinator.release_after_proven_cleanup()

            self.assertTrue(result.terminal)
            self.assertIsNotNone(result.error)
            self.assertEqual(snapshot.call_count, 1)
            self.assertEqual(settle.call_count, 1)
            diagnostic = coordinator._cleanup_terminal_diagnostic_snapshot()
            self.assertIsNotNone(diagnostic)
            self.assertTrue(
                getattr(
                    diagnostic,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertTrue(lease.retention_snapshot().terminal)

    def test_terminal_proof_never_reconciles_foreign_unresolved_handoff(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=True) as (
            _root,
            _source,
            _anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            handoff = claude_refresh_lock._OperationLockHandoff(lease._operation_lock)
            lease._publish_operation_handoff(handoff)
            handoff.acquire(
                timeout=0.01,
                first_control_flow=claude_refresh_lock._FirstControlFlowWinner(
                    lease._descriptor_bound_cleanup_fallback
                ),
            )
            descriptors = {
                *(lock.descriptor for lock in lease._locks),
                lease._legacy_parent_anchor.descriptor,
                lease._config_anchor.descriptor,
            }
            descriptor_identities = {
                descriptor: (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
                for descriptor in descriptors
            }
            outcomes: list[claude_linux._HostRefreshLockCleanupTerminalProof] = []
            failures: list[BaseException] = []

            def wait_from_foreign_thread() -> None:
                try:
                    outcomes.append(
                        coordinator._wait_for_cleanup_terminal_proof(
                            lease,
                            retry_scope="fixture",
                        )
                    )
                except BaseException as error:
                    failures.append(error)

            worker = threading.Thread(target=wait_from_foreign_thread, daemon=True)
            try:
                with (
                    mock.patch.object(
                        lease,
                        "_reconcile_pending_operation_handoff",
                        wraps=lease._reconcile_pending_operation_handoff,
                    ) as reconcile,
                    mock.patch.object(
                        lease,
                        "_settle_descriptor_bound_retention",
                        wraps=lease._settle_descriptor_bound_retention,
                    ) as settle,
                    mock.patch.object(
                        claude_linux.time,
                        "sleep",
                        return_value=None,
                    ),
                ):
                    worker.start()
                    worker.join(timeout=1.0)
                    self.assertFalse(worker.is_alive())
                    self.assertEqual(failures, [])
                    self.assertEqual(len(outcomes), 1)
                    self.assertFalse(outcomes[0].terminal)
                    self.assertIsNotNone(outcomes[0].diagnostic)
                    self.assertEqual(
                        settle.call_count,
                        claude_linux.CREDENTIAL_CLEANUP_STATE_MAX_ATTEMPTS,
                    )
                    reconcile.assert_not_called()
                self.assertIs(lease._pending_operation_handoff, handoff)
                self.assertTrue(handoff.needs_reconciliation)
                self.assertIsNot(handoff.owner_thread, worker)
                self.assertTrue(all(path.is_dir() for path in lease.paths))
                self.assertEqual(
                    {
                        descriptor: (
                            os.fstat(descriptor).st_dev,
                            os.fstat(descriptor).st_ino,
                        )
                        for descriptor in descriptors
                    },
                    descriptor_identities,
                )
            finally:
                lease._reconcile_pending_operation_handoff()

    def test_bounded_terminal_proof_replays_first_control_flow(self) -> None:
        for first_control_flow in (
            KeyboardInterrupt("injected terminal snapshot interrupt"),
            SystemExit("injected terminal snapshot exit"),
        ):
            with self.subTest(control_flow=type(first_control_flow).__name__):
                with self._host_cleanup_coordinator_fixture(with_lease=True) as (
                    _root,
                    _source,
                    _anchor,
                    coordinator,
                    lease,
                ):
                    assert lease is not None
                    limit = claude_linux.CREDENTIAL_CLEANUP_STATE_MAX_ATTEMPTS
                    snapshot_attempts = 0
                    settlement_attempts = 0
                    caught: list[BaseException] = []
                    real_retention_snapshot = lease.retention_snapshot

                    def fail_snapshot() -> (
                        claude_refresh_lock.ClaudeRefreshLockRetentionSnapshot
                    ):
                        nonlocal snapshot_attempts
                        snapshot_attempts += 1
                        if snapshot_attempts == 1:
                            raise first_control_flow
                        if snapshot_attempts <= limit:
                            raise OSError("injected later snapshot failure")
                        return real_retention_snapshot()

                    def fail_settlement(_reason: str) -> BaseException:
                        nonlocal settlement_attempts
                        settlement_attempts += 1
                        raise OSError("injected descriptor settlement failure")

                    def retain_source_without_settling_lease() -> None:
                        coordinator._retaining = True
                        coordinator._retention_reason = (
                            "injected terminal proof failure"
                        )
                        coordinator._retain_source_anchor()

                    def release() -> None:
                        try:
                            coordinator.release_after_proven_cleanup()
                        except BaseException as error:
                            caught.append(error)

                    with coordinator._state_lock:
                        coordinator._phase = (
                            claude_linux._HostRefreshLockCleanupPhase.WORKER_ENTERED
                        )
                    release_thread = threading.Thread(target=release, daemon=True)
                    with (
                        mock.patch.object(
                            lease,
                            "retention_snapshot",
                            side_effect=fail_snapshot,
                        ),
                        mock.patch.object(
                            lease,
                            "_settle_descriptor_bound_retention",
                            side_effect=fail_settlement,
                        ),
                        mock.patch.object(
                            coordinator,
                            "_fail_closed_worker",
                            side_effect=retain_source_without_settling_lease,
                        ),
                        mock.patch.object(
                            coordinator,
                            "_finalize_worker_retention",
                            return_value=None,
                        ),
                        mock.patch.object(
                            claude_linux.time,
                            "sleep",
                            return_value=None,
                        ),
                    ):
                        release_thread.start()
                        release_thread.join(timeout=1.0)

                    self.assertFalse(release_thread.is_alive())
                    self.assertEqual(caught, [first_control_flow])
                    self.assertEqual(snapshot_attempts, limit)
                    self.assertEqual(settlement_attempts, limit)
                    self.assertIs(
                        coordinator._phase_snapshot(),
                        claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
                    )
                    self.assertTrue(
                        getattr(
                            first_control_flow,
                            "_codex_claude_refresh_lock_descriptor_bound",
                            False,
                        )
                    )
                    self.assertTrue(all(path.is_dir() for path in lease.paths))

    def test_terminal_control_flow_uses_cached_empty_recovery_without_snapshot(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=True) as (
            _root,
            _source,
            _anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            control_flow = KeyboardInterrupt(
                "injected terminal control with no recovery diagnostic"
            )
            with coordinator._state_lock:
                coordinator._terminal_errors = ()
                coordinator._cleanup_terminal_proven = True
                coordinator._cleanup_terminal_diagnostic = None
                coordinator._phase = claude_linux._HostRefreshLockCleanupPhase.TERMINAL

            with (
                mock.patch.object(
                    lease,
                    "retention_snapshot",
                    side_effect=AssertionError(
                        "terminal control replay must not re-read lease state"
                    ),
                ) as snapshot,
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                coordinator._wait_until_terminal(local_errors=[control_flow])

            self.assertIs(raised.exception, control_flow)
            snapshot.assert_not_called()

    def test_dead_worker_takeover_waits_for_source_terminal_proof(self) -> None:
        class GatedSourceHandoffWatcher:
            def __init__(
                self,
                source_anchor: claude_linux._CredentialDirectoryAnchor,
                allow_source_handoff: threading.Event,
                source_handoff_attempted: threading.Event,
            ) -> None:
                self.source_anchor = source_anchor
                self.allow_source_handoff = allow_source_handoff
                self.source_handoff_attempted = source_handoff_attempted
                self.retain_anchor_calls = 0

            def may_have_started(self) -> bool:
                return True

            def request_stop(self) -> None:
                return None

            def wait_until_stopped(self) -> bool:
                return False

            def retain_source_anchor_after_timeout(self) -> None:
                self.retain_anchor_calls += 1
                self.source_handoff_attempted.set()
                if not self.allow_source_handoff.wait(timeout=2.0):
                    raise OSError(
                        "timed out waiting for injected source-handoff proof "
                        f"{self.retain_anchor_calls}"
                    )
                self.source_anchor.detach_to_watcher()

        with self._host_cleanup_coordinator_fixture(with_lease=True) as (
            root,
            _source,
            source_anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            carrier = root / "retained-carrier"
            config_dir = carrier / "config"
            config_dir.mkdir(parents=True)
            staged = claude_linux.StagedCredential(
                carrier_root=carrier,
                config_dir=config_dir,
                credential_path=config_dir / ".credentials.json",
                expires_at_ms=(time.time() + 3600) * 1000,
            )
            allow_source_handoff = threading.Event()
            source_handoff_attempted = threading.Event()
            watcher = GatedSourceHandoffWatcher(
                source_anchor,
                allow_source_handoff,
                source_handoff_attempted,
            )
            results: list[claude_linux._ClaudeRefreshLockCleanupResult] = []
            errors: list[BaseException] = []

            def release() -> None:
                try:
                    results.append(coordinator.release_after_proven_cleanup())
                except BaseException as error:
                    errors.append(error)

            coordinator.publish_watcher(staged, watcher)  # type: ignore[arg-type]
            with coordinator._state_lock:
                coordinator._phase = (
                    claude_linux._HostRefreshLockCleanupPhase.WORKER_ENTERED
                )
            release_thread = threading.Thread(target=release, daemon=True)
            returned_before_proof = False
            try:
                release_thread.start()
                self.assertTrue(source_handoff_attempted.wait(timeout=1.0))
                release_thread.join(timeout=0.05)
                returned_before_proof = not release_thread.is_alive()
                self.assertIs(
                    coordinator._phase_snapshot(),
                    claude_linux._HostRefreshLockCleanupPhase.CLEANUP,
                )
                self.assertFalse(coordinator._terminal.is_set())
                self.assertFalse(coordinator._source_terminal)
                self.assertFalse(source_anchor.detached_to_watcher)
                allow_source_handoff.set()
                release_thread.join(timeout=1.0)
            finally:
                allow_source_handoff.set()
                release_thread.join(timeout=1.0)

            self.assertFalse(returned_before_proof)
            self.assertFalse(release_thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(len(results), 1)
            self.assertTrue(results[0].terminal)
            self.assertTrue(coordinator._source_terminal)
            self.assertTrue(source_anchor.detached_to_watcher)
            self.assertIs(
                coordinator._phase_snapshot(),
                claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
            )
            self.assertTrue(lease.retention_snapshot().terminal)
            source_anchor.close_if_detached()

    def test_terminal_proof_bounds_persistent_source_handoff_failures(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(
            with_lease=False,
            allow_source_residue=True,
        ) as (
            root,
            _source,
            source_anchor,
            coordinator,
            no_lease,
        ):
            self.assertIsNone(no_lease)
            carrier = root / "retained-carrier"
            config_dir = carrier / "config"
            config_dir.mkdir(parents=True)
            staged = claude_linux.StagedCredential(
                carrier_root=carrier,
                config_dir=config_dir,
                credential_path=config_dir / ".credentials.json",
                expires_at_ms=(time.time() + 3600) * 1000,
            )
            coordinator.publish_watcher(staged, mock.Mock())
            source_anchor.detach_to_watcher()
            coordinator._mark_source_retention_required(None)
            attempts = 0

            def fail_source_handoff() -> None:
                nonlocal attempts
                attempts += 1
                if attempts > claude_linux.CREDENTIAL_CLEANUP_STATE_MAX_ATTEMPTS:
                    coordinator._source_terminal = True
                    raise AssertionError(
                        "terminal proof retried source handoff without a bound"
                    )
                raise OSError(f"injected persistent source handoff {attempts}")

            with (
                mock.patch.object(
                    coordinator,
                    "_retain_source_anchor",
                    side_effect=fail_source_handoff,
                ),
                mock.patch.object(claude_linux.time, "sleep", return_value=None),
            ):
                coordinator._wait_for_cleanup_terminal_proof(
                    None,
                    retry_scope="fixture",
                )

            self.assertEqual(
                attempts,
                claude_linux.CREDENTIAL_CLEANUP_STATE_MAX_ATTEMPTS,
            )
            self.assertTrue(coordinator._source_terminal)
            self.assertIs(
                source_anchor.disposition,
                claude_linux._CredentialDirectoryAnchorDisposition.DESCRIPTOR_RESIDUE,
            )
            diagnostic = source_anchor.descriptor_residue_diagnostic
            self.assertIsNotNone(diagnostic)
            assert diagnostic is not None
            self.assertIs(
                getattr(
                    diagnostic,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                ),
                True,
            )
            self.assertIs(
                getattr(
                    diagnostic,
                    "_codex_claude_source_descriptor_residue",
                    False,
                ),
                True,
            )
            self.assertTrue(
                all(isinstance(error, BaseException) for error in coordinator._errors)
            )

    def test_terminal_proof_bounds_residue_terminalizer_failures(self) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=False) as (
            root,
            _source,
            _source_anchor,
            coordinator,
            no_lease,
        ):
            self.assertIsNone(no_lease)
            carrier = root / "retained-carrier"
            config_dir = carrier / "config"
            config_dir.mkdir(parents=True)
            staged = claude_linux.StagedCredential(
                carrier_root=carrier,
                config_dir=config_dir,
                credential_path=config_dir / ".credentials.json",
                expires_at_ms=(time.time() + 3600) * 1000,
            )
            coordinator.publish_watcher(staged, mock.Mock())
            coordinator._mark_source_retention_required(None)

            with (
                mock.patch.object(
                    coordinator,
                    "_retain_source_anchor",
                    side_effect=OSError("injected persistent source handoff"),
                ),
                mock.patch.object(
                    coordinator._source_anchor,
                    "settle_descriptor_bound_residue",
                    side_effect=OSError("injected persistent residue settlement"),
                ) as settle_residue,
                mock.patch.object(claude_linux.time, "sleep", return_value=None),
                self.assertRaisesRegex(
                    claude_linux.LinuxCredentialInspectionInconclusive,
                    "did not publish a terminal disposition after bounded retries",
                ),
            ):
                coordinator._wait_for_cleanup_terminal_proof(
                    None,
                    retry_scope="fixture",
                )

            self.assertEqual(
                settle_residue.call_count,
                claude_linux.CREDENTIAL_CLEANUP_STATE_MAX_ATTEMPTS,
            )
            self.assertFalse(coordinator._source_terminal)
            self.assertTrue(
                all(isinstance(error, BaseException) for error in coordinator._errors)
            )

    def test_dead_worker_takeover_releases_failed_synchronous_claim(self) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=False) as (
            _root,
            _source,
            _source_anchor,
            coordinator,
            no_lease,
        ):
            self.assertIsNone(no_lease)
            proof_failures = [
                claude_linux.LinuxCredentialInspectionInconclusive(
                    f"injected terminal-proof failure {attempt}"
                )
                for attempt in range(2)
            ]

            with (
                mock.patch.object(
                    coordinator,
                    "_wait_for_cleanup_terminal_proof",
                    side_effect=proof_failures,
                ) as terminal_proof,
                mock.patch.object(
                    coordinator._terminal,
                    "wait",
                    return_value=False,
                ),
            ):
                for failure in proof_failures:
                    with self.assertRaises(
                        claude_linux.LinuxCredentialInspectionInconclusive
                    ) as raised:
                        coordinator.cancel_without_lease()
                    self.assertIs(raised.exception, failure)
                    self.assertFalse(coordinator._synchronous_cleanup_claimed)

            self.assertEqual(terminal_proof.call_count, 2)
            self.assertIs(
                coordinator._phase_snapshot(),
                claude_linux._HostRefreshLockCleanupPhase.CLEANUP,
            )
            self.assertFalse(coordinator._terminal.is_set())

    def test_terminal_proof_latches_residue_before_interrupted_publication(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(
            with_lease=False,
            allow_source_residue=True,
        ) as (
            root,
            _source,
            source_anchor,
            coordinator,
            no_lease,
        ):
            self.assertIsNone(no_lease)
            carrier = root / "retained-carrier"
            config_dir = carrier / "config"
            config_dir.mkdir(parents=True)
            staged = claude_linux.StagedCredential(
                carrier_root=carrier,
                config_dir=config_dir,
                credential_path=config_dir / ".credentials.json",
                expires_at_ms=(time.time() + 3600) * 1000,
            )
            coordinator.publish_watcher(staged, mock.Mock())
            source_anchor.detach_to_watcher()
            coordinator._mark_source_retention_required(None)
            source_descriptors = source_anchor._descriptors
            control_flow = KeyboardInterrupt(
                "injected descriptor-residue diagnostic publication interruption"
            )

            with (
                mock.patch.object(
                    coordinator,
                    "_retain_source_anchor",
                    side_effect=OSError("injected persistent source handoff"),
                ),
                self._interrupt_attribute_assignment(
                    claude_linux._CredentialDirectoryAnchor._descriptor_residue_diagnostic_locked,
                    target=source_anchor,
                    attribute_name="_descriptor_residue_diagnostic",
                    error=control_flow,
                ),
                mock.patch.object(claude_linux.time, "sleep", return_value=None),
            ):
                coordinator._wait_for_cleanup_terminal_proof(
                    None,
                    retry_scope="fixture",
                )

            self.assertTrue(coordinator._source_terminal)
            self.assertIs(
                source_anchor.disposition,
                claude_linux._CredentialDirectoryAnchorDisposition.DESCRIPTOR_RESIDUE,
            )
            diagnostic = source_anchor.descriptor_residue_diagnostic
            self.assertIsNotNone(diagnostic)
            assert diagnostic is not None
            self.assertIsNot(diagnostic, control_flow)
            self.assertTrue(any(error is control_flow for error in coordinator._errors))
            self.assertTrue(
                getattr(
                    diagnostic,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertTrue(
                getattr(
                    diagnostic,
                    "_codex_claude_source_descriptor_residue",
                    False,
                )
            )

            with mock.patch.object(
                claude_linux.os,
                "close",
                wraps=claude_linux.os.close,
            ) as close_descriptor:
                with self.assertRaises(
                    claude_linux.LinuxCredentialInspectionInconclusive
                ) as first:
                    source_anchor.close_if_owned()
                self.assertIs(first.exception, diagnostic)

                with self.assertRaises(
                    claude_linux.LinuxCredentialInspectionInconclusive
                ) as descriptor_read:
                    _ = source_anchor.descriptor
                self.assertIs(descriptor_read.exception, diagnostic)

                with self.assertRaises(
                    claude_linux.LinuxCredentialInspectionInconclusive
                ) as legacy_descriptor_read:
                    _ = source_anchor.legacy_parent_descriptor
                self.assertIs(legacy_descriptor_read.exception, diagnostic)

                with self.assertRaises(
                    claude_linux.LinuxCredentialInspectionInconclusive
                ) as stability_check:
                    source_anchor.assert_stable(owner_uid=os.getuid())
                self.assertIs(stability_check.exception, diagnostic)

                with self.assertRaises(
                    claude_linux.LinuxCredentialInspectionInconclusive
                ) as repeated:
                    source_anchor.close_if_detached()
                self.assertIs(repeated.exception, diagnostic)
                close_descriptor.assert_not_called()
                for descriptor in source_descriptors:
                    os.fstat(descriptor)

    def test_terminal_proof_retries_interrupted_residue_diagnostic_read(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(
            with_lease=False,
            allow_source_residue=True,
        ) as (
            root,
            _source,
            source_anchor,
            coordinator,
            no_lease,
        ):
            self.assertIsNone(no_lease)
            carrier = root / "retained-carrier"
            config_dir = carrier / "config"
            config_dir.mkdir(parents=True)
            staged = claude_linux.StagedCredential(
                carrier_root=carrier,
                config_dir=config_dir,
                credential_path=config_dir / ".credentials.json",
                expires_at_ms=(time.time() + 3600) * 1000,
            )
            coordinator.publish_watcher(staged, mock.Mock())
            source_anchor.detach_to_watcher()
            coordinator._mark_source_retention_required(None)
            control_flow = KeyboardInterrupt(
                "injected source-anchor residue diagnostic read interruption"
            )
            real_diagnostic_getter = claude_linux._CredentialDirectoryAnchor.descriptor_residue_diagnostic.fget
            assert real_diagnostic_getter is not None
            diagnostic_reads = 0

            def read_residue_diagnostic(
                anchor: claude_linux._CredentialDirectoryAnchor,
            ) -> claude_linux.LinuxCredentialInspectionInconclusive | None:
                nonlocal diagnostic_reads
                diagnostic_reads += 1
                if diagnostic_reads == 1:
                    raise control_flow
                return real_diagnostic_getter(anchor)

            with (
                mock.patch.object(
                    coordinator,
                    "_retain_source_anchor",
                    side_effect=OSError("injected persistent source handoff"),
                ),
                mock.patch.object(
                    claude_linux._CredentialDirectoryAnchor,
                    "descriptor_residue_diagnostic",
                    new=property(read_residue_diagnostic),
                ),
                mock.patch.object(claude_linux.time, "sleep", return_value=None),
            ):
                coordinator._wait_for_cleanup_terminal_proof(
                    None,
                    retry_scope="fixture",
                )

            self.assertEqual(diagnostic_reads, 2)
            self.assertTrue(coordinator._source_terminal)
            self.assertTrue(any(error is control_flow for error in coordinator._errors))
            self.assertIs(
                source_anchor.disposition,
                claude_linux._CredentialDirectoryAnchorDisposition.DESCRIPTOR_RESIDUE,
            )

    def test_worker_owner_read_interruption_keeps_source_requirement(self) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=True) as (
            _root,
            _source,
            source_anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            owner_read_control = KeyboardInterrupt(
                "injected ordinary-worker owner lease-read interruption"
            )
            caught: list[BaseException] = []

            def retain() -> None:
                try:
                    coordinator.retain(
                        reason="injected ordinary-worker owner-read failure"
                    )
                except BaseException as error:
                    caught.append(error)

            retain_thread = threading.Thread(target=retain, daemon=True)
            try:
                with mock.patch.object(
                    claude_linux._HostRefreshLockCleanupOwner,
                    "lease",
                    new_callable=mock.PropertyMock,
                    side_effect=owner_read_control,
                ):
                    coordinator._thread.start()
                    retain_thread.start()
                    retain_thread.join(timeout=1.0)
            finally:
                if retain_thread.ident is not None:
                    retain_thread.join(timeout=1.0)

            self.assertFalse(retain_thread.is_alive())
            self.assertEqual(caught, [owner_read_control])
            self.assertTrue(coordinator._source_retention_required)
            self.assertTrue(coordinator._source_terminal)
            self.assertIs(
                source_anchor.disposition,
                claude_linux._CredentialDirectoryAnchorDisposition.CLOSED,
            )
            self.assertIs(
                coordinator._phase_snapshot(),
                claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
            )
            self.assertTrue(lease.retention_snapshot().terminal)

    def test_dead_worker_owner_read_interruption_keeps_source_requirement(
        self,
    ) -> None:
        class TransferringWatcher:
            def __init__(
                self,
                source_anchor: claude_linux._CredentialDirectoryAnchor,
                handoff_called: threading.Event,
            ) -> None:
                self.source_anchor = source_anchor
                self.handoff_called = handoff_called

            def may_have_started(self) -> bool:
                return True

            def request_stop(self) -> None:
                return None

            def wait_until_stopped(self) -> bool:
                return False

            def retain_source_anchor_after_timeout(self) -> None:
                self.source_anchor.detach_to_watcher()
                self.handoff_called.set()

        with self._host_cleanup_coordinator_fixture(with_lease=False) as (
            root,
            _source,
            source_anchor,
            coordinator,
            no_lease,
        ):
            self.assertIsNone(no_lease)
            carrier = root / "retained-carrier"
            config_dir = carrier / "config"
            config_dir.mkdir(parents=True)
            staged = claude_linux.StagedCredential(
                carrier_root=carrier,
                config_dir=config_dir,
                credential_path=config_dir / ".credentials.json",
                expires_at_ms=(time.time() + 3600) * 1000,
            )
            handoff_called = threading.Event()
            watcher = TransferringWatcher(source_anchor, handoff_called)
            owner_read_control = KeyboardInterrupt(
                "injected dead-worker owner lease-read interruption"
            )
            caught: list[BaseException] = []

            def retain() -> None:
                try:
                    coordinator.retain(reason="injected dead-worker owner-read failure")
                except BaseException as error:
                    caught.append(error)

            coordinator.publish_watcher(staged, watcher)  # type: ignore[arg-type]
            with coordinator._state_lock:
                coordinator._phase = (
                    claude_linux._HostRefreshLockCleanupPhase.WORKER_ENTERED
                )
            retain_thread = threading.Thread(target=retain, daemon=True)
            try:
                with mock.patch.object(
                    claude_linux._HostRefreshLockCleanupOwner,
                    "lease",
                    new_callable=mock.PropertyMock,
                    side_effect=owner_read_control,
                ):
                    retain_thread.start()
                    retain_thread.join(timeout=1.0)
            finally:
                if retain_thread.ident is not None:
                    retain_thread.join(timeout=1.0)

            self.assertFalse(retain_thread.is_alive())
            self.assertEqual(caught, [owner_read_control])
            self.assertTrue(handoff_called.is_set())
            self.assertTrue(coordinator._source_retention_required)
            self.assertTrue(coordinator._source_terminal)
            self.assertTrue(source_anchor.detached_to_watcher)
            self.assertIs(
                coordinator._phase_snapshot(),
                claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
            )
            source_anchor.close_if_detached()

    def test_worker_bounds_unprovable_lease_terminal(self) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=True) as (
            _root,
            _source,
            _anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            limit = claude_linux.CREDENTIAL_CLEANUP_STATE_MAX_ATTEMPTS
            snapshot_attempts = 0
            settlement_attempts = 0
            retain_failures: list[BaseException] = []

            def fail_snapshot() -> (
                claude_refresh_lock.ClaudeRefreshLockRetentionSnapshot
            ):
                nonlocal snapshot_attempts
                snapshot_attempts += 1
                raise OSError(
                    f"injected persistent worker terminal snapshot {snapshot_attempts}"
                )

            def fail_settlement(_reason: str) -> BaseException:
                nonlocal settlement_attempts
                settlement_attempts += 1
                raise OSError(
                    f"injected persistent worker settlement {settlement_attempts}"
                )

            def retain_without_settling(
                _decision: claude_linux._HostRefreshLockCleanupDecision,
            ) -> None:
                lease._deletion_prohibited = True
                lease._heartbeat_stop.set()
                coordinator._retaining = True
                coordinator._retain_source_anchor()

            def retain() -> None:
                try:
                    coordinator.retain(reason="injected ordinary-worker terminal proof")
                except BaseException as error:
                    retain_failures.append(error)

            retain_thread = threading.Thread(target=retain, daemon=True)
            with (
                mock.patch.object(
                    lease,
                    "retention_snapshot",
                    side_effect=fail_snapshot,
                ),
                mock.patch.object(
                    lease,
                    "_settle_descriptor_bound_retention",
                    side_effect=fail_settlement,
                ),
                mock.patch.object(
                    coordinator,
                    "_execute_worker_decision",
                    side_effect=retain_without_settling,
                ),
                mock.patch.object(
                    coordinator,
                    "_finalize_worker_retention",
                    return_value=None,
                ),
                mock.patch.object(claude_linux.time, "sleep", return_value=None),
            ):
                coordinator._thread.start()
                retain_thread.start()
                retain_thread.join(timeout=1.0)

            self.assertFalse(retain_thread.is_alive())
            self.assertEqual(len(retain_failures), 1)
            self.assertIsInstance(
                retain_failures[0],
                claude_linux.LinuxCredentialInspectionInconclusive,
            )
            self.assertIn("proven terminal", str(retain_failures[0]))
            self.assertEqual(snapshot_attempts, limit)
            self.assertEqual(settlement_attempts, limit)
            self.assertIs(
                coordinator._phase_snapshot(),
                claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
            )
            self.assertFalse(lease.retention_snapshot().terminal)
            self.assertTrue(lease._deletion_prohibited)
            self.assertTrue(all(path.is_dir() for path in lease.paths))

    def test_cancel_without_lease_preserves_wait_control_flow(
        self,
    ) -> None:
        for control_flow in (
            KeyboardInterrupt("injected terminal-wait interruption"),
            SystemExit("injected terminal-wait exit"),
        ):
            with self.subTest(control_flow=type(control_flow).__name__):
                with self._host_cleanup_coordinator_fixture(with_lease=False) as (
                    _root,
                    _source,
                    _anchor,
                    coordinator,
                    _lease,
                ):
                    liveness_error = OSError(
                        "injected terminal liveness observation failure"
                    )
                    setattr(
                        liveness_error,
                        "_codex_claude_refresh_lock_descriptor_bound",
                        True,
                    )
                    real_terminal_set = coordinator._terminal.set
                    wait_calls = 0

                    def interrupt_then_observe_terminal(
                        *,
                        timeout: float,
                    ) -> bool:
                        nonlocal wait_calls
                        self.assertEqual(timeout, 0.1)
                        wait_calls += 1
                        if wait_calls == 1:
                            raise control_flow
                        return coordinator._terminal.is_set()

                    def publish_terminal_then_fail_liveness() -> bool:
                        with coordinator._state_lock:
                            coordinator._terminal_errors = ()
                            coordinator._phase = (
                                claude_linux._HostRefreshLockCleanupPhase.TERMINAL
                            )
                        real_terminal_set()
                        raise liveness_error

                    with (
                        mock.patch.object(
                            coordinator._terminal,
                            "wait",
                            side_effect=interrupt_then_observe_terminal,
                        ),
                        mock.patch.object(
                            coordinator._thread,
                            "is_alive",
                            side_effect=publish_terminal_then_fail_liveness,
                        ),
                        self.assertRaises(type(control_flow)) as raised,
                    ):
                        coordinator.cancel_without_lease()

                    self.assertIs(raised.exception, control_flow)
                    self.assertTrue(coordinator._terminal.is_set())
                    self.assertIsNone(coordinator.owner.lease)
                    self.assertIs(
                        coordinator._decision,
                        claude_linux._HostRefreshLockCleanupDecision.CANCEL,
                    )
                    self.assertTrue(
                        getattr(
                            raised.exception,
                            "_codex_claude_refresh_lock_descriptor_bound",
                            False,
                        )
                    )
                    self.assertIn(
                        str(liveness_error),
                        self._visible_explicit_cause_text(raised.exception),
                    )

    def test_terminal_wait_control_flow_keeps_lease_recovery_evidence(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=True) as (
            _root,
            _source,
            _anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            recovery = lease._settle_descriptor_bound_retention(
                "injected terminal-wait retained residue"
            )
            control_flow = KeyboardInterrupt(
                "injected retained terminal-wait interruption"
            )
            wait_calls = 0

            def interrupt_then_observe_terminal(
                *,
                timeout: float,
            ) -> bool:
                nonlocal wait_calls
                self.assertEqual(timeout, 0.1)
                wait_calls += 1
                if wait_calls == 1:
                    raise control_flow
                with coordinator._state_lock:
                    coordinator._terminal_errors = ()
                    coordinator._cleanup_terminal_proven = True
                    coordinator._cleanup_terminal_diagnostic = recovery
                    coordinator._phase = (
                        claude_linux._HostRefreshLockCleanupPhase.TERMINAL
                    )
                return coordinator._terminal.is_set()

            with (
                mock.patch.object(
                    coordinator._terminal,
                    "wait",
                    side_effect=interrupt_then_observe_terminal,
                ),
                mock.patch.object(
                    coordinator._thread,
                    "is_alive",
                    return_value=True,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                coordinator.retain(
                    reason="injected retained terminal-wait control flow"
                )

            self.assertIs(raised.exception, control_flow)
            self.assertIs(
                lease.retention_snapshot().diagnostic,
                recovery,
            )
            self.assertTrue(
                getattr(
                    raised.exception,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertFalse(lease.released)
            self.assertTrue(all(path.is_dir() for path in lease.paths))

    def test_terminal_observation_failures_wait_for_cleanup_proof(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=True) as (
            _root,
            _source,
            _anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            cleanup_entered = threading.Event()
            allow_cleanup = threading.Event()
            wait_control = KeyboardInterrupt(
                "injected terminal observation interruption"
            )
            liveness_error = OSError("injected terminal liveness observation failure")
            retain_errors: list[BaseException] = []
            real_execute = coordinator._execute_worker_decision

            def delayed_cleanup(
                decision: claude_linux._HostRefreshLockCleanupDecision,
            ) -> None:
                cleanup_entered.set()
                allow_cleanup.wait(timeout=1.0)
                real_execute(decision)

            def retain() -> None:
                try:
                    coordinator.retain(reason="injected delayed terminal proof")
                except BaseException as error:
                    retain_errors.append(error)

            retain_thread = threading.Thread(target=retain, daemon=True)
            try:
                with (
                    mock.patch.object(
                        coordinator,
                        "_execute_worker_decision",
                        side_effect=delayed_cleanup,
                    ),
                    mock.patch.object(
                        coordinator._terminal,
                        "wait",
                        side_effect=wait_control,
                    ),
                    mock.patch.object(
                        coordinator._thread,
                        "is_alive",
                        side_effect=liveness_error,
                    ),
                ):
                    coordinator._thread.start()
                    retain_thread.start()
                    self.assertTrue(cleanup_entered.wait(timeout=0.5))
                    retain_thread.join(timeout=0.1)
                    returned_before_cleanup = not retain_thread.is_alive()
                    allow_cleanup.set()
                    retain_thread.join(timeout=1.0)

                self.assertFalse(
                    returned_before_cleanup,
                    "waiter propagated before cleanup reached terminal proof",
                )
                self.assertFalse(retain_thread.is_alive())
                self.assertEqual(retain_errors, [wait_control])
                self.assertIs(
                    coordinator._phase_snapshot(),
                    claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
                )
                self.assertTrue(lease.retention_snapshot().terminal)
                heartbeat = lease._heartbeat_thread
                assert heartbeat is not None
                heartbeat.join(timeout=1.0)
                self.assertFalse(heartbeat.is_alive())
            finally:
                allow_cleanup.set()
                if retain_thread.ident is not None:
                    retain_thread.join(timeout=1.0)

    def test_terminal_waiters_keep_local_control_flow_isolated(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=False) as (
            _root,
            _source,
            _anchor,
            coordinator,
            _lease,
        ):
            controls = {
                "waiter-a": KeyboardInterrupt("injected waiter-a control"),
                "waiter-b": SystemExit("injected waiter-b control"),
            }
            first_wait = threading.Barrier(2)
            wait_counts = {name: 0 for name in controls}
            caught: dict[str, BaseException] = {}

            def wait_for_terminal(*, timeout: float) -> bool:
                self.assertEqual(timeout, 0.1)
                name = threading.current_thread().name
                wait_counts[name] += 1
                if wait_counts[name] == 1:
                    first_wait.wait(timeout=1.0)
                    raise controls[name]
                with coordinator._state_lock:
                    coordinator._terminal_errors = ()
                    coordinator._phase = (
                        claude_linux._HostRefreshLockCleanupPhase.TERMINAL
                    )
                return True

            def wait() -> None:
                name = threading.current_thread().name
                try:
                    coordinator._wait_until_terminal()
                except BaseException as error:
                    caught[name] = error

            waiters = [
                threading.Thread(target=wait, name=name, daemon=True)
                for name in controls
            ]
            with (
                mock.patch.object(
                    coordinator._terminal,
                    "wait",
                    side_effect=wait_for_terminal,
                ),
                mock.patch.object(
                    coordinator._thread,
                    "is_alive",
                    return_value=True,
                ),
            ):
                for waiter in waiters:
                    waiter.start()
                for waiter in waiters:
                    waiter.join(timeout=1.0)

            self.assertTrue(all(not waiter.is_alive() for waiter in waiters))
            self.assertEqual(set(caught), set(controls))
            for name, control_flow in controls.items():
                self.assertIs(caught[name], control_flow)
            self.assertEqual(coordinator._errors, [])

    def test_terminal_waiter_errors_are_bounded_per_stage(self) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=False) as (
            _root,
            _source,
            _anchor,
            coordinator,
            _lease,
        ):
            limit = claude_linux.CREDENTIAL_CLEANUP_STATE_MAX_ATTEMPTS
            target = limit + 3
            control_flow = KeyboardInterrupt(
                "injected waiter control after terminal-wait overflow"
            )
            wait_calls = 0
            liveness_calls = 0
            join_calls = 0
            captured_local_errors: list[BaseException] = []
            phase_at_selection: list[claude_linux._HostRefreshLockCleanupPhase] = []
            real_raise_selected_control_flow = coordinator._raise_selected_control_flow

            def fail_terminal_wait(*, timeout: float) -> bool:
                nonlocal wait_calls
                self.assertEqual(timeout, 0.1)
                wait_calls += 1
                if wait_calls == limit + 1:
                    raise control_flow
                raise OSError(f"injected waiter terminal-wait failure {wait_calls}")

            def fail_worker_liveness() -> bool:
                nonlocal liveness_calls
                liveness_calls += 1
                raise OSError(
                    f"injected waiter worker-liveness failure {liveness_calls}"
                )

            def fail_worker_join(*, timeout: float) -> None:
                nonlocal join_calls
                self.assertEqual(timeout, 0.1)
                join_calls += 1
                if (
                    wait_calls >= target
                    and liveness_calls >= target
                    and join_calls >= 2 * target
                ):
                    with coordinator._state_lock:
                        coordinator._terminal_errors = ()
                        coordinator._phase = (
                            claude_linux._HostRefreshLockCleanupPhase.TERMINAL
                        )
                raise OSError(f"injected waiter worker-join failure {join_calls}")

            def capture_selection(
                *,
                local_errors: list[BaseException],
                worker_errors: tuple[BaseException, ...],
                claim_worker_control_flow: bool,
            ) -> None:
                captured_local_errors.extend(local_errors)
                phase_at_selection.append(coordinator._phase_snapshot())
                real_raise_selected_control_flow(
                    local_errors=local_errors,
                    worker_errors=worker_errors,
                    claim_worker_control_flow=claim_worker_control_flow,
                )

            with coordinator._state_lock:
                coordinator._phase = (
                    claude_linux._HostRefreshLockCleanupPhase.WORKER_ENTERED
                )
            with (
                mock.patch.object(
                    coordinator._terminal,
                    "wait",
                    side_effect=fail_terminal_wait,
                ),
                mock.patch.object(
                    coordinator._thread,
                    "is_alive",
                    side_effect=fail_worker_liveness,
                ),
                mock.patch.object(
                    coordinator._thread,
                    "join",
                    side_effect=fail_worker_join,
                ),
                mock.patch.object(
                    coordinator,
                    "_raise_selected_control_flow",
                    side_effect=capture_selection,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                coordinator._wait_until_terminal()

            self.assertIs(raised.exception, control_flow)
            self.assertEqual(
                phase_at_selection,
                [claude_linux._HostRefreshLockCleanupPhase.TERMINAL],
            )
            self.assertEqual(
                sum(error is control_flow for error in captured_local_errors),
                1,
            )
            for prefix in (
                "injected waiter terminal-wait failure",
                "injected waiter worker-liveness failure",
                "injected waiter worker-join failure",
            ):
                self.assertLessEqual(
                    sum(
                        str(error).startswith(prefix) for error in captured_local_errors
                    ),
                    limit,
                )
            for stage in ("terminal wait", "worker liveness", "worker join"):
                self.assertEqual(
                    sum(
                        f"additional waiter-local {stage} failures were suppressed"
                        in str(error)
                        for error in captured_local_errors
                    ),
                    1,
                )
            self.assertLessEqual(
                len(captured_local_errors),
                1 + 3 * (limit + 1),
            )
            self.assertEqual(coordinator._errors, [])

    def test_claimed_worker_control_survives_cached_recovery_read_failure(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=False) as (
            _root,
            _source,
            _anchor,
            coordinator,
            _lease,
        ):
            worker_control = KeyboardInterrupt("injected terminal worker interruption")
            attachment_control = SystemExit(
                "injected cached recovery-read interruption"
            )
            with coordinator._state_lock:
                coordinator._errors.append(worker_control)
                coordinator._worker_first_control_flow = worker_control
                coordinator._terminal_errors = (worker_control,)
                coordinator._phase = claude_linux._HostRefreshLockCleanupPhase.TERMINAL

            with (
                mock.patch.object(
                    coordinator,
                    "_cleanup_terminal_diagnostic_snapshot",
                    side_effect=attachment_control,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                coordinator._wait_until_terminal()

            self.assertIs(raised.exception, worker_control)
            self.assertIn(
                str(attachment_control),
                self._visible_explicit_cause_text(worker_control),
            )
            self.assertEqual(coordinator._wait_until_terminal(), ())

    def test_cleanup_coordinator_startup_publication_failures_are_bounded(
        self,
    ) -> None:
        for publication in ("_worker_entered", "_ready"):
            with self.subTest(publication=publication):
                with self._host_cleanup_coordinator_fixture(with_lease=False) as (
                    _root,
                    _source,
                    _anchor,
                    coordinator,
                    _lease,
                ):
                    event = getattr(coordinator, publication)
                    real_ready_set = coordinator._ready.set
                    startup_error = KeyboardInterrupt(
                        f"injected {publication} publication failure"
                    )
                    start_errors: list[BaseException] = []

                    def start() -> None:
                        try:
                            coordinator.start()
                        except BaseException as error:
                            start_errors.append(error)

                    start_thread = threading.Thread(target=start, daemon=True)
                    with mock.patch.object(
                        event,
                        "set",
                        side_effect=startup_error,
                    ):
                        start_thread.start()
                        start_thread.join(timeout=0.5)
                        was_stuck = start_thread.is_alive()

                    if was_stuck:
                        real_ready_set()
                        start_thread.join(timeout=1.0)

                    self.assertFalse(
                        was_stuck,
                        f"{publication} failure left start() unbounded",
                    )
                    self.assertFalse(start_thread.is_alive())
                    self.assertTrue(start_errors)
                    self.assertIs(
                        coordinator._phase_snapshot(),
                        claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
                    )
                    self.assertTrue(coordinator._terminal.is_set())

    def test_decision_fallback_failure_retains_published_lease(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=True) as (
            _root,
            _source,
            _anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            wait_error = KeyboardInterrupt("injected sticky decision fallback failure")
            fallback_wait_calls = 0

            def fail_fallback_until_gate(*, timeout: float) -> bool:
                nonlocal fallback_wait_calls
                self.assertEqual(timeout, 0.1)
                fallback_wait_calls += 1
                if (
                    fallback_wait_calls
                    <= claude_linux.CREDENTIAL_CLEANUP_STATE_MAX_ATTEMPTS
                ):
                    raise wait_error
                return False

            with (
                mock.patch.object(
                    coordinator,
                    "_wait_for_decision",
                    side_effect=OSError("injected decision condition failure"),
                ),
                mock.patch.object(
                    coordinator._condition,
                    "wait",
                    side_effect=fail_fallback_until_gate,
                ),
            ):
                coordinator._thread.start()
                coordinator._thread.join(timeout=0.5)
                was_stuck = coordinator._thread.is_alive()

            if was_stuck:
                with coordinator._state_lock:
                    coordinator._decision = (
                        claude_linux._HostRefreshLockCleanupDecision.RETAIN
                    )
                    coordinator._retention_reason = "test gate retention"
                with coordinator._condition:
                    coordinator._condition.notify_all()
                coordinator._thread.join(timeout=1.0)

            self.assertFalse(
                was_stuck,
                "sticky decision fallback failure left worker unbounded",
            )
            self.assertFalse(coordinator._thread.is_alive())
            self.assertIs(
                coordinator._phase_snapshot(),
                claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
            )
            self.assertTrue(coordinator._terminal.is_set())
            snapshot = lease.retention_snapshot()
            self.assertTrue(snapshot.terminal)
            self.assertFalse(lease.released)
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            heartbeat.join(timeout=1.0)
            self.assertFalse(heartbeat.is_alive())
            self.assertTrue(all(path.is_dir() for path in lease.paths))

    def test_closed_publication_gate_rejects_late_acquire_before_heartbeat(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=False) as (
            _root,
            source,
            source_anchor,
            coordinator,
            _lease,
        ):
            primary_path = source.parent / self.PROTOCOL.primary_lock_name
            legacy_path = pathlib.Path(f"{source.parent}{self.PROTOCOL.legacy_suffix}")
            coordinator.owner.close_publication()

            with (
                mock.patch.object(
                    claude_refresh_lock.ClaudeRefreshLockLease,
                    "_start_heartbeat",
                    autospec=True,
                ) as heartbeat_start,
                self.assertRaises(
                    claude_refresh_lock.ClaudeRefreshLockCompromised
                ) as raised,
            ):
                claude_linux.acquire_claude_refresh_lock(
                    source.parent,
                    protocol=self.PROTOCOL,
                    owner=coordinator.owner,
                    timeout_seconds=0,
                    config_dir_fd=source_anchor.descriptor,
                    legacy_parent_dir_fd=(source_anchor.legacy_parent_descriptor),
                    require_explicit_context_release=True,
                )

            self.assertIn("no longer accepts lease publication", str(raised.exception))
            heartbeat_start.assert_not_called()
            self.assertIsNone(coordinator.owner.lease)
            self.assertFalse(primary_path.exists())
            self.assertFalse(legacy_path.exists())

    def test_worker_retries_publication_gate_close_before_terminal(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=True) as (
            _root,
            _source,
            _anchor,
            coordinator,
            lease,
        ):
            assert lease is not None
            gate_control = KeyboardInterrupt(
                "injected worker publication-gate close interruption"
            )
            real_close_publication = coordinator.owner.close_publication
            close_calls = 0

            def interrupt_gate_close_once() -> (
                claude_refresh_lock.ClaudeRefreshLockLease | None
            ):
                nonlocal close_calls
                close_calls += 1
                if close_calls == 1:
                    raise gate_control
                return real_close_publication()

            with (
                mock.patch.object(
                    coordinator.owner,
                    "close_publication",
                    side_effect=interrupt_gate_close_once,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                coordinator._thread.start()
                coordinator.retain(
                    reason="injected publication-gate close interruption"
                )

            self.assertIs(raised.exception, gate_control)
            self.assertGreaterEqual(close_calls, 2)
            self.assertIs(
                coordinator._phase_snapshot(),
                claude_linux._HostRefreshLockCleanupPhase.TERMINAL,
            )
            self.assertTrue(coordinator._source_terminal)
            self.assertTrue(lease.retention_snapshot().terminal)
            heartbeat = lease._heartbeat_thread
            assert heartbeat is not None
            heartbeat.join(timeout=1.0)
            self.assertFalse(heartbeat.is_alive())

            self.assertEqual(
                coordinator.retain(
                    reason="injected publication-gate close interruption"
                ),
                (),
            )

    def test_finalization_adopts_lease_published_after_initial_failure(
        self,
    ) -> None:
        with self._host_cleanup_coordinator_fixture(with_lease=False) as (
            _root,
            source,
            source_anchor,
            coordinator,
            _lease,
        ):
            published: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
            wait_error = KeyboardInterrupt(
                "injected decision failure before late lease publication"
            )
            real_enter_cleanup = coordinator._enter_cleanup_phase_and_close_publication

            def publish_then_enter_cleanup(
                *,
                require_source_retention: bool = False,
            ) -> claude_refresh_lock.ClaudeRefreshLockLease | None:
                if published:
                    return real_enter_cleanup(
                        require_source_retention=require_source_retention,
                    )
                lease = claude_linux.acquire_claude_refresh_lock(
                    source.parent,
                    protocol=self.PROTOCOL,
                    owner=coordinator.owner,
                    timeout_seconds=0,
                    config_dir_fd=source_anchor.descriptor,
                    legacy_parent_dir_fd=(source_anchor.legacy_parent_descriptor),
                    require_explicit_context_release=True,
                )
                coordinator.owner.transfer(lease)
                published.append(lease)
                return real_enter_cleanup(
                    require_source_retention=require_source_retention,
                )

            try:
                with (
                    mock.patch.object(
                        coordinator,
                        "_wait_for_decision",
                        side_effect=wait_error,
                    ),
                    mock.patch.object(
                        coordinator._condition,
                        "wait",
                        side_effect=wait_error,
                    ),
                    mock.patch.object(
                        coordinator,
                        "_enter_cleanup_phase_and_close_publication",
                        side_effect=publish_then_enter_cleanup,
                    ),
                ):
                    coordinator._thread.start()
                    coordinator._thread.join(timeout=1.0)

                self.assertFalse(coordinator._thread.is_alive())
                self.assertEqual(len(published), 1)
                lease = published[0]
                self.assertTrue(coordinator._source_terminal)
                self.assertTrue(lease.retention_snapshot().terminal)
                self.assertFalse(lease.released)
                heartbeat = lease._heartbeat_thread
                assert heartbeat is not None
                heartbeat.join(timeout=1.0)
                self.assertFalse(heartbeat.is_alive())
                self.assertTrue(all(path.is_dir() for path in lease.paths))
            finally:
                for lease in published:
                    self._dispose_refresh_lock_fixture(lease)

    def test_mask_handoffs_restore_and_release_host_lease(self) -> None:
        now = time.time()
        for interrupted_call in (1, 2, 3):
            with self.subTest(interrupted_call=interrupted_call):
                with tempfile.TemporaryDirectory() as temporary:
                    root = pathlib.Path(temporary).resolve()
                    helper = root / "helper"
                    helper.mkdir(mode=0o700)
                    source = self._credential(
                        root / ".credentials.json",
                        expires_at_ms=(now - 60) * 1000,
                    )
                    forwarded = claude_linux.ForwardedSignal(signal.SIGTERM)
                    block_calls = 0
                    restored_masks: list[set[signal.Signals] | None] = []
                    host_leases: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
                    real_acquire = claude_linux.acquire_claude_refresh_lock
                    real_block_forwarded_signals = claude_linux.block_forwarded_signals
                    real_restore_signal_mask = claude_linux.restore_signal_mask
                    original_mask = signal.pthread_sigmask(
                        signal.SIG_BLOCK,
                        set(),
                    )

                    def block_forwarded_signals(
                        *,
                        signal_mask_owner: object | None = None,
                    ) -> set[signal.Signals] | None:
                        nonlocal block_calls
                        block_calls += 1
                        previous_mask = real_block_forwarded_signals(
                            signal_mask_owner=signal_mask_owner,
                        )
                        if block_calls == interrupted_call:
                            raise forwarded
                        return previous_mask

                    def restore_signal_mask(
                        previous_mask: set[signal.Signals] | None,
                    ) -> None:
                        restored_masks.append(previous_mask)
                        real_restore_signal_mask(previous_mask)

                    def acquire_refresh_lock(
                        config_path: os.PathLike[str] | str,
                        **kwargs: object,
                    ) -> claude_refresh_lock.ClaudeRefreshLockLease:
                        lease = real_acquire(config_path, **kwargs)
                        if pathlib.Path(config_path) == source.parent:
                            self.assertIs(
                                kwargs.get("require_explicit_context_release"),
                                True,
                            )
                            host_leases.append(lease)
                        return lease

                    with (
                        mock.patch.object(
                            claude_linux,
                            "block_forwarded_signals",
                            side_effect=block_forwarded_signals,
                        ),
                        mock.patch.object(
                            claude_linux,
                            "restore_signal_mask",
                            side_effect=restore_signal_mask,
                        ),
                        mock.patch.object(
                            claude_linux,
                            "acquire_claude_refresh_lock",
                            side_effect=acquire_refresh_lock,
                        ),
                        self.assertRaises(claude_linux.ForwardedSignal) as caught,
                    ):
                        with claude_linux.stage_claude_credentials(
                            source,
                            helper,
                            now=now,
                            refresh_lock_protocol=self.PROTOCOL,
                        ):
                            pass

                    self.assertIs(caught.exception, forwarded)
                    self.assertGreaterEqual(block_calls, interrupted_call)
                    self.assertEqual(
                        restored_masks,
                        [original_mask] * block_calls,
                    )
                    self.assertEqual(list(helper.iterdir()), [])
                    if interrupted_call == 1:
                        self.assertEqual(host_leases, [])
                        continue
                    self.assertGreaterEqual(len(host_leases), 1)
                    host_lease = host_leases[0]
                    self.assertTrue(host_lease.retention_snapshot().terminal)
                    heartbeat = host_lease._heartbeat_thread
                    assert heartbeat is not None
                    self.assertFalse(heartbeat.is_alive())
                    for path in host_lease.paths:
                        self.assertFalse(path.exists(), path)

    def test_signal_mask_restore_retries_after_failure(self) -> None:
        previous_mask: set[signal.Signals] = {signal.SIGUSR1}

        for restore_path in ("cleanup", "handoff"):
            with self.subTest(restore_path=restore_path):
                restore_failure = OSError(
                    errno.EIO,
                    "injected signal-mask restore failure",
                )
                restore_calls = 0

                def restore_signal_mask(
                    restored_mask: set[signal.Signals] | None,
                ) -> None:
                    nonlocal restore_calls
                    restore_calls += 1
                    self.assertIs(restored_mask, previous_mask)
                    if restore_calls == 1:
                        raise restore_failure

                if restore_path == "cleanup":

                    def block_forwarded_signals(
                        *,
                        signal_mask_owner: object | None = None,
                    ) -> set[signal.Signals]:
                        assert signal_mask_owner is not None
                        signal_mask_owner.publish(previous_mask)
                        return previous_mask

                    retain_unmasked_cleanup = mock.Mock()
                    with (
                        mock.patch.object(
                            claude_linux,
                            "block_forwarded_signals",
                            side_effect=block_forwarded_signals,
                        ),
                        mock.patch.object(
                            claude_linux,
                            "restore_signal_mask",
                            side_effect=restore_signal_mask,
                        ),
                        claude_linux._defer_forwarded_signals_during_cleanup(
                            retain_unmasked_cleanup=retain_unmasked_cleanup,
                        ) as cleanup_signals,
                    ):
                        pass
                    retain_unmasked_cleanup.assert_not_called()
                    self.assertEqual(cleanup_signals.errors, [restore_failure])
                else:
                    signal_mask_owner = claude_linux.ForwardedSignalMaskOwner()
                    signal_mask_owner.publish(previous_mask)
                    with (
                        mock.patch.object(
                            claude_linux,
                            "restore_signal_mask",
                            side_effect=restore_signal_mask,
                        ),
                        self.assertRaises(OSError) as caught,
                    ):
                        claude_linux._restore_forwarded_signal_mask_owner(
                            signal_mask_owner,
                            None,
                        )
                    self.assertIs(caught.exception, restore_failure)
                    self.assertFalse(signal_mask_owner.active)

                self.assertEqual(restore_calls, 2)

    def test_missing_signal_mask_bounds_persistent_retention_failure(
        self,
    ) -> None:
        mask_failure = OSError(
            errno.EPERM,
            "injected forwarded-signal mask failure",
        )
        retention_failure = OSError(
            errno.EIO,
            "injected persistent retention failure",
        )
        unexpected_success = RuntimeError(
            "unbounded retention retry unexpectedly succeeded",
        )
        retention_calls = 0

        def retain_unmasked_cleanup(
            _errors: list[BaseException],
        ) -> BaseException:
            nonlocal retention_calls
            retention_calls += 1
            if retention_calls <= claude_linux.UNMASKED_CREDENTIAL_CLEANUP_MAX_ATTEMPTS:
                raise retention_failure
            return unexpected_success

        with (
            mock.patch.object(
                claude_linux,
                "block_forwarded_signals",
                side_effect=mask_failure,
            ),
            claude_linux._defer_forwarded_signals_during_cleanup(
                retain_unmasked_cleanup=retain_unmasked_cleanup,
            ) as cleanup_signals,
        ):
            pass

        self.assertEqual(
            retention_calls,
            claude_linux.UNMASKED_CREDENTIAL_CLEANUP_MAX_ATTEMPTS,
        )
        self.assertFalse(cleanup_signals.mask_established)
        self.assertIsInstance(
            cleanup_signals.fail_closed_error,
            claude_linux.LinuxCredentialInspectionInconclusive,
        )
        assert cleanup_signals.fail_closed_error is not None
        self.assertIs(
            cleanup_signals.fail_closed_error.__cause__,
            retention_failure,
        )
        self.assertTrue(
            getattr(
                cleanup_signals.fail_closed_error,
                "_codex_claude_refresh_persistence_failed",
                False,
            )
        )
        self.assertEqual(
            cleanup_signals.errors,
            [mask_failure, mask_failure]
            + [retention_failure]
            * claude_linux.UNMASKED_CREDENTIAL_CLEANUP_MAX_ATTEMPTS,
        )

    def test_persistent_unmasked_retention_failure_keeps_carrier_metadata(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            helper = root / "worker-helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            staged_credentials: list[claude_linux.StagedCredential] = []
            thread_errors: list[BaseException] = []
            retention_failure = OSError(
                errno.EIO,
                "injected persistent retention failure",
            )

            def stage_on_worker() -> None:
                try:
                    with claude_linux.stage_claude_credentials(
                        source,
                        helper,
                        now=now,
                    ) as staged:
                        staged_credentials.append(staged)
                except BaseException as error:
                    thread_errors.append(error)

            with (
                mock.patch.object(
                    claude_linux,
                    "_retain_unmasked_credential_cleanup",
                    side_effect=retention_failure,
                ) as retain,
                mock.patch.object(
                    claude_linux,
                    "_cleanup_staged_credential",
                ) as cleanup_staged,
            ):
                worker = threading.Thread(
                    target=stage_on_worker,
                    name="persistent-unmasked-retention-worker",
                    daemon=True,
                )
                worker.start()
                worker.join(timeout=3.0)

            self.assertFalse(worker.is_alive())
            self.assertEqual(
                retain.call_count,
                claude_linux.UNMASKED_CREDENTIAL_CLEANUP_MAX_ATTEMPTS,
            )
            self.assertEqual(len(staged_credentials), 1)
            self.assertEqual(len(thread_errors), 1)
            self.assertIsInstance(
                thread_errors[0],
                claude_linux.LinuxCredentialInspectionInconclusive,
            )
            cleanup_staged.assert_not_called()
            self._assert_retained_recovery_carrier(
                error=thread_errors[0],
                staged=staged_credentials[0],
                helper=helper,
                expected_refresh_token=self.SYNTH_REFRESH_A,
            )

    def test_missing_signal_mask_never_starts_threads_or_destroys_carrier(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            helper = root / "unsupported-helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            with (
                mock.patch.object(
                    claude_linux,
                    "block_forwarded_signals",
                    return_value=None,
                ),
                mock.patch.object(
                    claude_linux,
                    "acquire_claude_refresh_lock",
                ) as acquire_refresh_lock,
                mock.patch.object(
                    claude_linux._StagedCredentialWatcher,
                    "start",
                    autospec=True,
                ) as start_watcher,
                self.assertRaises(claude_linux.LinuxCredentialInspectionInconclusive),
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ):
                    self.fail("missing signal mask exposed a credential")

            acquire_refresh_lock.assert_not_called()
            start_watcher.assert_not_called()
            self.assertEqual(list(helper.iterdir()), [])

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            helper = root / "worker-helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            staged_credentials: list[claude_linux.StagedCredential] = []
            thread_errors: list[BaseException] = []

            def stage_on_worker() -> None:
                try:
                    with claude_linux.stage_claude_credentials(
                        source,
                        helper,
                        now=now,
                    ) as staged:
                        staged_credentials.append(staged)
                except BaseException as error:
                    thread_errors.append(error)

            with (
                mock.patch.object(
                    claude_linux,
                    "_writeback_refreshed_credential",
                ) as writeback,
                mock.patch.object(
                    claude_linux,
                    "_cleanup_staged_credential",
                ) as cleanup_staged,
            ):
                worker = threading.Thread(
                    target=stage_on_worker,
                    name="missing-signal-mask-worker",
                    daemon=True,
                )
                worker.start()
                worker.join(timeout=3.0)

            self.assertFalse(worker.is_alive())
            self.assertEqual(len(staged_credentials), 1)
            self.assertEqual(len(thread_errors), 1)
            self.assertIsInstance(
                thread_errors[0],
                claude_linux.LinuxCredentialInspectionInconclusive,
            )
            writeback.assert_not_called()
            cleanup_staged.assert_not_called()
            self._assert_retained_recovery_carrier(
                error=thread_errors[0],
                staged=staged_credentials[0],
                helper=helper,
                expected_refresh_token=self.SYNTH_REFRESH_A,
            )

    def test_missing_watcher_mask_uses_masked_retention_coordinator(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            block_calls = 0
            real_block_forwarded_signals = claude_linux.block_forwarded_signals
            real_acquire = claude_linux.acquire_claude_refresh_lock
            host_leases: list[claude_refresh_lock.ClaudeRefreshLockLease] = []

            def block_forwarded_signals(
                *,
                signal_mask_owner: object | None = None,
            ) -> set[signal.Signals] | None:
                nonlocal block_calls
                block_calls += 1
                if block_calls == 1:
                    assert signal_mask_owner is not None
                    return real_block_forwarded_signals(
                        signal_mask_owner=signal_mask_owner,
                    )
                return None

            def acquire_refresh_lock(
                config_path: os.PathLike[str] | str,
                **kwargs: object,
            ) -> claude_refresh_lock.ClaudeRefreshLockLease:
                if pathlib.Path(config_path) == source.parent:
                    self.assertIs(
                        kwargs.get("require_explicit_context_release"),
                        True,
                    )
                lease = real_acquire(config_path, **kwargs)
                if pathlib.Path(config_path) == source.parent:
                    host_leases.append(lease)
                return lease

            with (
                mock.patch.object(
                    claude_linux,
                    "block_forwarded_signals",
                    side_effect=block_forwarded_signals,
                ),
                mock.patch.object(
                    claude_linux,
                    "acquire_claude_refresh_lock",
                    side_effect=acquire_refresh_lock,
                ),
                mock.patch.object(
                    claude_linux._StagedCredentialWatcher,
                    "start",
                    autospec=True,
                ) as start_watcher,
                self.assertRaises(
                    claude_linux.LinuxCredentialInspectionInconclusive
                ) as caught,
            ):
                with claude_linux.stage_claude_credentials(
                    source,
                    helper,
                    now=now,
                    refresh_lock_protocol=self.PROTOCOL,
                ):
                    self.fail("missing watcher mask exposed a credential")

            start_watcher.assert_not_called()
            self.assertGreaterEqual(block_calls, 3)
            self.assertEqual(len(host_leases), 1)
            host_lease = host_leases[0]
            snapshot = host_lease.retention_snapshot()
            self.assertTrue(snapshot.terminal)
            self.assertFalse(host_lease.released)
            heartbeat = host_lease._heartbeat_thread
            assert heartbeat is not None
            self.assertFalse(heartbeat.is_alive())
            self.assertTrue(all(path.exists() for path in host_lease.paths))
            self.assertEqual(
                getattr(
                    caught.exception,
                    "_codex_claude_refresh_lock_paths",
                    (),
                ),
                (),
            )
            self.assertTrue(
                getattr(
                    caught.exception,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            retained_carrier = getattr(
                caught.exception,
                "_codex_claude_retained_credential_carrier",
                None,
            )
            self.assertIsInstance(retained_carrier, str)
            assert isinstance(retained_carrier, str)
            self.assertTrue(pathlib.Path(retained_carrier).is_dir())

    def test_unmasked_cleanup_retains_carrier_and_abandons_host_lease(
        self,
    ) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            helper = root / "helper"
            helper.mkdir(mode=0o700)
            source = self._credential(
                root / ".credentials.json",
                expires_at_ms=(now - 60) * 1000,
            )
            first = claude_linux.ForwardedSignal(signal.SIGTERM)
            later = claude_linux.ForwardedSignal(signal.SIGINT)
            retention_interruptions: list[BaseException] = [
                claude_linux.ForwardedSignal(signal.SIGINT),
                KeyboardInterrupt("injected fail-closed retention call interruption"),
            ]
            terminal_wait_interruptions: list[BaseException] = [
                claude_linux.ForwardedSignal(signal.SIGINT),
                KeyboardInterrupt("injected retention terminal-wait interruption"),
            ]
            block_calls = 0
            retention_calls = 0
            terminal_wait_calls = 0
            host_leases: list[claude_refresh_lock.ClaudeRefreshLockLease] = []
            watchers: list[claude_linux._StagedCredentialWatcher] = []
            staged_credentials: list[claude_linux.StagedCredential] = []
            real_acquire = claude_linux.acquire_claude_refresh_lock
            real_block_forwarded_signals = claude_linux.block_forwarded_signals
            real_watcher_start = claude_linux._StagedCredentialWatcher.start
            real_retain_unmasked = claude_linux._retain_unmasked_credential_cleanup
            real_wait_until_terminal = (
                claude_linux._HostRefreshLockCleanupCoordinator._wait_until_terminal
            )
            cleanup_code = (
                claude_linux._stage_claude_credentials_anchored.__wrapped__.__code__
            )
            cleanup_assignment_offsets = {
                instruction.offset
                for instruction in dis.get_instructions(cleanup_code)
                if instruction.opname == "STORE_FAST"
                and instruction.argval == "writeback_error"
            }
            self.assertTrue(cleanup_assignment_offsets)
            previous_trace = sys.gettrace()
            signal_injected = False

            def block_forwarded_signals(
                *,
                signal_mask_owner: object | None = None,
            ) -> set[signal.Signals]:
                nonlocal block_calls
                block_calls += 1
                if block_calls <= 2:
                    assert signal_mask_owner is not None
                    return real_block_forwarded_signals(
                        signal_mask_owner=signal_mask_owner,
                    )
                if block_calls == 3:
                    raise first
                raise OSError(errno.EIO, "injected signal-mask failure")

            def acquire_refresh_lock(
                config_path: os.PathLike[str] | str,
                **kwargs: object,
            ) -> claude_refresh_lock.ClaudeRefreshLockLease:
                lease = real_acquire(config_path, **kwargs)
                if pathlib.Path(config_path) == source.parent:
                    host_leases.append(lease)
                return lease

            def start_watcher(
                watcher: claude_linux._StagedCredentialWatcher,
            ) -> None:
                watchers.append(watcher)
                real_watcher_start(watcher)

            def retain_unmasked_cleanup(
                **kwargs: object,
            ) -> BaseException:
                nonlocal retention_calls
                retention_calls += 1
                if retention_interruptions:
                    raise retention_interruptions.pop(0)
                return real_retain_unmasked(**kwargs)

            def wait_until_terminal(
                coordinator: (claude_linux._HostRefreshLockCleanupCoordinator),
                *,
                local_errors: list[BaseException] | None = None,
            ) -> tuple[BaseException, ...]:
                nonlocal terminal_wait_calls
                terminal_wait_calls += 1
                if terminal_wait_interruptions:
                    raise terminal_wait_interruptions.pop(0)
                return real_wait_until_terminal(
                    coordinator,
                    local_errors=local_errors,
                )

            def trace(frame: object, event: str, _argument: object) -> object:
                nonlocal signal_injected
                if frame.f_code is cleanup_code:
                    frame.f_trace_opcodes = True
                    if (
                        event == "opcode"
                        and not signal_injected
                        and block_calls >= 4
                        and frame.f_lasti in cleanup_assignment_offsets
                    ):
                        signal_injected = True
                        raise later
                return trace

            try:
                with (
                    mock.patch.object(
                        claude_linux,
                        "block_forwarded_signals",
                        side_effect=block_forwarded_signals,
                    ),
                    mock.patch.object(
                        claude_linux,
                        "acquire_claude_refresh_lock",
                        side_effect=acquire_refresh_lock,
                    ),
                    mock.patch.object(
                        claude_linux._StagedCredentialWatcher,
                        "start",
                        autospec=True,
                        side_effect=start_watcher,
                    ),
                    mock.patch.object(
                        claude_linux,
                        "_retain_unmasked_credential_cleanup",
                        side_effect=retain_unmasked_cleanup,
                    ),
                    mock.patch.object(
                        claude_linux._HostRefreshLockCleanupCoordinator,
                        "_wait_until_terminal",
                        autospec=True,
                        side_effect=wait_until_terminal,
                    ),
                    self.assertRaises(claude_linux.ForwardedSignal) as caught,
                ):
                    sys.settrace(trace)
                    with claude_linux.stage_claude_credentials(
                        source,
                        helper,
                        now=now,
                        refresh_lock_protocol=self.PROTOCOL,
                    ) as staged:
                        staged_credentials.append(staged)

                self.assertTrue(signal_injected)
                self.assertEqual(retention_calls, 5)
                self.assertEqual(terminal_wait_calls, 3)
                self.assertIs(caught.exception, first)
                self.assertEqual(len(host_leases), 1)
                self.assertEqual(len(staged_credentials), 1)
                host_lease = host_leases[0]
                snapshot = host_lease.retention_snapshot()
                self.assertTrue(snapshot.terminal)
                self.assertIsNotNone(snapshot.diagnostic)
                self.assertEqual(
                    getattr(
                        snapshot.diagnostic,
                        "_codex_claude_refresh_lock_paths",
                        (),
                    ),
                    (),
                )
                self.assertTrue(
                    getattr(
                        snapshot.diagnostic,
                        "_codex_claude_refresh_lock_descriptor_bound",
                        False,
                    )
                )
                heartbeat = host_lease._heartbeat_thread
                assert heartbeat is not None
                self.assertFalse(heartbeat.is_alive())
                self._assert_retained_recovery_carrier(
                    error=caught.exception,
                    staged=staged_credentials[0],
                    helper=helper,
                    expected_refresh_token=self.SYNTH_REFRESH_A,
                )
                self.assertEqual(
                    getattr(
                        caught.exception,
                        "_codex_claude_refresh_lock_paths",
                        (),
                    ),
                    (),
                )
            finally:
                sys.settrace(previous_trace)
                for watcher in watchers:
                    watcher.request_stop()
                    watcher.wait_until_stopped()
                for lease in host_leases:
                    if lease.retention_snapshot().terminal:
                        continue
                    lease._deletion_prohibited = True
                    lease._heartbeat_stop.set()
                    try:
                        lease.abandon("test cleanup after injected signal")
                    except claude_refresh_lock.ClaudeRefreshLockError:
                        pass

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
            abandonment_diagnostic = (
                claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive(
                    "fixture descriptor-bound host refresh-lock abandonment"
                )
            )
            setattr(
                abandonment_diagnostic,
                "_codex_claude_refresh_lock_descriptor_bound",
                True,
            )
            host_refresh_lock = self._CoordinatorLeaseFixture(
                assert_held_side_effect=[
                    None,
                    claude_linux.ClaudeRefreshLockError("fixture lock compromise"),
                ],
                abandonment_diagnostic=abandonment_diagnostic,
            )
            acquired_locks = iter((host_refresh_lock, staged_refresh_lock))

            def acquire_refresh_lock(
                _config_dir: os.PathLike[str] | str,
                **kwargs: object,
            ) -> mock.Mock:
                lease = next(acquired_locks)
                owner = kwargs["owner"]
                assert isinstance(
                    owner,
                    claude_refresh_lock.ClaudeRefreshLockOwner,
                )
                owner._publish(lease)
                return lease

            with (
                mock.patch.object(
                    claude_linux,
                    "acquire_claude_refresh_lock",
                    side_effect=acquire_refresh_lock,
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
            host_refresh_lock.release.assert_not_called()
            host_refresh_lock.abandon.assert_called_once()
            self.assertTrue(
                getattr(
                    raised.exception,
                    "_codex_claude_refresh_lock_descriptor_bound",
                    False,
                )
            )
            self.assertIn(
                "descriptor-bound lock directories may remain",
                str(raised.exception),
            )
            self.assertEqual(
                acquire_refresh_lock.call_args_list,
                [
                    mock.call(
                        source.parent,
                        protocol=self.PROTOCOL,
                        owner=mock.ANY,
                        config_dir_fd=mock.ANY,
                        legacy_parent_dir_fd=mock.ANY,
                        require_explicit_context_release=True,
                    ),
                    mock.call(
                        staged.config_dir,
                        protocol=self.PROTOCOL,
                        owner=mock.ANY,
                        timeout_seconds=(
                            claude_linux.STAGED_CREDENTIAL_LOCK_TIMEOUT_SECONDS
                        ),
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

    def test_cleanup_note_legacy_fallback_respects_context_visibility(self) -> None:
        class LegacyError(RuntimeError):
            add_note = None

        sensitive_path = "/fixture/private/suppressed-linux-context/.credentials.json"
        for suppress_context in (False, True):
            with self.subTest(suppress_context=suppress_context):
                marker = sensitive_path if suppress_context else "visible-linux-context"
                original_context = RuntimeError(marker)
                primary = LegacyError("primary failure")
                primary.__context__ = original_context
                primary.__suppress_context__ = suppress_context

                claude_linux._add_cleanup_note(
                    primary,
                    OSError("cleanup failed"),
                )

                diagnostic = primary.__cause__
                self.assertIsInstance(
                    diagnostic,
                    claude_linux.LinuxCredentialCleanupDiagnostic,
                )
                assert diagnostic is not None
                if suppress_context:
                    self.assertIsNone(diagnostic.__context__)
                else:
                    self.assertIs(diagnostic.__context__, original_context)
                self.assertIs(primary.__context__, original_context)
                formatted = "".join(
                    traceback.format_exception(
                        type(primary),
                        primary,
                        primary.__traceback__,
                    )
                )
                if suppress_context:
                    self.assertNotIn(marker, formatted)
                else:
                    self.assertIn(marker, formatted)

    def test_host_lock_recovery_is_visible_on_python_310_fallback(self) -> None:
        class LegacyInterrupt(KeyboardInterrupt):
            add_note = None

        cleanup_interrupt = LegacyInterrupt("injected cleanup interruption")
        abandonment_diagnostic = (
            claude_refresh_lock.ClaudeRefreshLockCleanupInconclusive(
                "descriptor-bound lock directories may remain"
            )
        )
        setattr(
            abandonment_diagnostic,
            "_codex_claude_refresh_lock_descriptor_bound",
            True,
        )

        claude_linux._attach_host_refresh_lock_recovery(
            cleanup_interrupt,
            abandonment_diagnostic,
        )

        self.assertTrue(
            getattr(
                cleanup_interrupt,
                "_codex_claude_refresh_lock_descriptor_bound",
                False,
            )
        )
        diagnostic = cleanup_interrupt.__cause__
        self.assertIsInstance(
            diagnostic,
            claude_linux.LinuxCredentialCleanupDiagnostic,
        )
        assert diagnostic is not None
        self.assertIn(
            "descriptor-bound lock directories may remain",
            str(diagnostic),
        )

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
                            "accessToken": self.SYNTH_ACCESS_A,
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
