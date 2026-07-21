"""Enter an inherited directory descriptor before replacing this process."""

from __future__ import annotations

import os
import sys


def main() -> int:
    if len(sys.argv) < 4:
        print(
            "usage: fd_exec.py DIRECTORY_FD STATUS_FD COMMAND [ARG ...]",
            file=sys.stderr,
        )
        return 64
    try:
        directory_fd = int(sys.argv[1])
        status_fd = None if sys.argv[2] == "-" else int(sys.argv[2])
    except ValueError:
        print("fd_exec.py: descriptor arguments must be integers", file=sys.stderr)
        return 64
    command = sys.argv[3:]
    try:
        if status_fd is not None:
            os.set_inheritable(status_fd, False)
        os.fchdir(directory_fd)
        os.close(directory_fd)
        os.execvpe(command[0], command, os.environ)
    except OSError as error:
        payload = f"{error.errno or 5}\n{error}".encode("utf-8", errors="replace")
        if status_fd is not None:
            try:
                os.write(status_fd, payload)
            except OSError:
                pass
        else:
            sys.stderr.buffer.write(b"fd_exec.py: launch-error: " + payload + b"\n")
            sys.stderr.buffer.flush()
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
