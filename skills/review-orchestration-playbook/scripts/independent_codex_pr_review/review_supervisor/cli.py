from __future__ import annotations

import argparse
import pathlib
import signal
import sys
from collections.abc import Sequence
from typing import Any

from .constants import (
    LOW_LEVEL_HELPER_REVIEW_CONTRACT,
    NAMED_LANE_ELIGIBLE,
    VERSION,
    default_checkout_parent,
    default_retention_root,
)
from .custody import custody_helper_main
from .errors import SupervisorError
from .final_transport import run_fifo_reader
from .runtime import (
    attempt_supervisor_main,
    authorization_helper_main,
    checkout_worker_main,
    phase_helper_main,
    prompt_helper_main,
    prompt_verifier_main,
)
from .secureio import canonical_json, require_python_313
from .supervisor import cleanup, final_result, preflight, recover, release, run, status


def _absolute(value: str) -> pathlib.Path:
    path = pathlib.Path(value).expanduser()
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    if any(part in {".", ".."} for part in path.parts):
        raise argparse.ArgumentTypeError("path must not contain dot components")
    return path


def _add_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--helper-state", required=True, type=_absolute)
    parser.add_argument("--repo", required=True, type=_absolute)
    parser.add_argument("--base", required=True, dest="base_sha")
    parser.add_argument("--head", required=True, dest="head_sha")
    parser.add_argument("--pr-url", required=True)
    parser.add_argument(
        "--retention-root",
        type=_absolute,
        default=default_retention_root(),
    )
    parser.add_argument(
        "--checkout-parent",
        type=_absolute,
        default=default_checkout_parent(),
    )
    parser.add_argument("--git", dest="git_executable", default="/usr/bin/git")
    parser.add_argument("--codex", dest="codex_executable")


def _public_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="independent-codex-pr-review",
        description="Task-scoped supervisor for low-level independent Codex review.",
    )
    parser.add_argument("--version", action="version", version=VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight_parser = subparsers.add_parser(
        "preflight",
        help="Authenticate and admit an exact retained-helper handoff without launching Codex.",
    )
    _add_source_arguments(preflight_parser)

    run_parser = subparsers.add_parser(
        "run",
        help="Run the admitted independent reviewer under the contracted supervisor.",
    )
    _add_source_arguments(run_parser)

    status_parser = subparsers.add_parser(
        "status", help="Read compact durable attempt status."
    )
    status_parser.add_argument(
        "--retention-root",
        type=_absolute,
        default=default_retention_root(),
    )
    status_parser.add_argument("--attempt-dir", type=_absolute)

    final_parser = subparsers.add_parser(
        "final",
        help="Revalidate and return the sole sealed reviewer final artifact.",
    )
    final_parser.add_argument(
        "--retention-root",
        type=_absolute,
        default=default_retention_root(),
    )
    final_parser.add_argument("--attempt-dir", required=True, type=_absolute)

    recover_parser = subparsers.add_parser(
        "recover",
        help="Recover an outstanding process reservation only after a proved boot change.",
    )
    recover_parser.add_argument(
        "--retention-root",
        type=_absolute,
        default=default_retention_root(),
    )
    recover_parser.add_argument("--attempt-dir", required=True, type=_absolute)

    release_parser = subparsers.add_parser(
        "release",
        help="Explicitly release exactly settled held evidence.",
    )
    release_parser.add_argument(
        "--retention-root",
        type=_absolute,
        default=default_retention_root(),
    )
    release_parser.add_argument("--attempt-dir", required=True, type=_absolute)
    release_parser.add_argument(
        "--reason",
        required=True,
        choices=("resolved", "handoff-complete"),
    )

    cleanup_parser = subparsers.add_parser(
        "cleanup",
        help="Reclaim one explicitly released, exactly settled attempt.",
    )
    cleanup_parser.add_argument(
        "--retention-root",
        type=_absolute,
        default=default_retention_root(),
    )
    cleanup_parser.add_argument("--attempt-dir", required=True, type=_absolute)
    return parser


def _internal_parser(mode: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=f"independent-codex-pr-review {mode}")
    if mode == "_phase-helper":
        parser.add_argument("--attempt-dir", required=True, type=_absolute)
        parser.add_argument("--control-fd", required=True, type=int)
        parser.add_argument("--lease-fd", required=True, type=int)
        parser.add_argument("--root-fd", required=True, type=int)
        parser.add_argument("--attempt-fd", required=True, type=int)
        parser.add_argument("--token", required=True)
    elif mode == "_prompt-helper":
        parser.add_argument("--attempt-dir", required=True, type=_absolute)
        parser.add_argument("--control-fd", required=True, type=int)
        parser.add_argument("--lease-fd", required=True, type=int)
        parser.add_argument("--root-fd", required=True, type=int)
        parser.add_argument("--attempt-fd", required=True, type=int)
        parser.add_argument("--token", required=True)
    elif mode == "_prompt-verifier":
        parser.add_argument("--attempt-dir", required=True, type=_absolute)
        parser.add_argument("--control-fd", required=True, type=int)
        parser.add_argument("--lease-fd", required=True, type=int)
        parser.add_argument("--root-fd", required=True, type=int)
        parser.add_argument("--attempt-fd", required=True, type=int)
        parser.add_argument("--token", required=True)
    elif mode == "_authorization-helper":
        parser.add_argument("--attempt-dir", required=True, type=_absolute)
        parser.add_argument("--control-fd", required=True, type=int)
        parser.add_argument("--lease-fd", required=True, type=int)
        parser.add_argument("--root-fd", required=True, type=int)
        parser.add_argument("--attempt-fd", required=True, type=int)
        parser.add_argument("--outer-liveness-fd", required=True, type=int)
        parser.add_argument("--token", required=True)
    elif mode == "_checkout-worker":
        parser.add_argument("--attempt-dir", required=True, type=_absolute)
        parser.add_argument("--control-fd", required=True, type=int)
        parser.add_argument("--lease-fd", required=True, type=int)
        parser.add_argument("--root-fd", required=True, type=int)
        parser.add_argument("--attempt-fd", required=True, type=int)
        parser.add_argument("--source-fd", required=True, type=int)
        parser.add_argument("--token", required=True)
    elif mode == "_fifo-reader":
        parser.add_argument("--control-fd", required=True, type=int)
        parser.add_argument("--fifo", required=True, type=_absolute)
        parser.add_argument("--final-path", required=True, type=_absolute)
        parser.add_argument("--token", required=True)
    elif mode == "_attempt-supervisor":
        parser.add_argument("--entrypoint", required=True, type=_absolute)
        parser.add_argument("--attempt-dir", required=True, type=_absolute)
        parser.add_argument("--control-fd", required=True, type=int)
        parser.add_argument("--lease-fd", required=True, type=int)
        parser.add_argument("--root-fd", required=True, type=int)
        parser.add_argument("--attempt-fd", required=True, type=int)
        parser.add_argument("--handoff-token", required=True)
    elif mode == "_custody-helper":
        parser.add_argument("--control-fd", required=True, type=int)
        parser.add_argument("--state-dir", required=True, type=_absolute)
        parser.add_argument("--repo", required=True, type=_absolute)
        parser.add_argument("--base", required=True)
        parser.add_argument("--head", required=True)
        parser.add_argument("--token", required=True)
    else:
        raise ValueError("unknown internal mode")
    return parser


def _run_internal(mode: str, argv: Sequence[str]) -> int:
    arguments = _internal_parser(mode).parse_args(argv)
    if mode == "_phase-helper":
        return phase_helper_main(
            attempt_dir=arguments.attempt_dir,
            control_fd=arguments.control_fd,
            lease_fd=arguments.lease_fd,
            root_fd=arguments.root_fd,
            attempt_fd=arguments.attempt_fd,
            token=arguments.token,
        )
    if mode == "_prompt-helper":
        return prompt_helper_main(
            attempt_dir=arguments.attempt_dir,
            control_fd=arguments.control_fd,
            lease_fd=arguments.lease_fd,
            root_fd=arguments.root_fd,
            attempt_fd=arguments.attempt_fd,
            token=arguments.token,
        )
    if mode == "_prompt-verifier":
        return prompt_verifier_main(
            attempt_dir=arguments.attempt_dir,
            control_fd=arguments.control_fd,
            lease_fd=arguments.lease_fd,
            root_fd=arguments.root_fd,
            attempt_fd=arguments.attempt_fd,
            token=arguments.token,
        )
    if mode == "_authorization-helper":
        return authorization_helper_main(
            attempt_dir=arguments.attempt_dir,
            control_fd=arguments.control_fd,
            lease_fd=arguments.lease_fd,
            root_fd=arguments.root_fd,
            attempt_fd=arguments.attempt_fd,
            outer_liveness_fd=arguments.outer_liveness_fd,
            token=arguments.token,
        )
    if mode == "_checkout-worker":
        return checkout_worker_main(
            attempt_dir=arguments.attempt_dir,
            control_fd=arguments.control_fd,
            lease_fd=arguments.lease_fd,
            root_fd=arguments.root_fd,
            attempt_fd=arguments.attempt_fd,
            source_fd=arguments.source_fd,
            token=arguments.token,
        )
    if mode == "_fifo-reader":
        return run_fifo_reader(
            control_fd=arguments.control_fd,
            fifo=arguments.fifo,
            final_path=arguments.final_path,
            token=arguments.token,
        )
    if mode == "_custody-helper":
        return custody_helper_main(
            control_fd=arguments.control_fd,
            state_dir=arguments.state_dir,
            repo=arguments.repo,
            base_sha=arguments.base,
            head_sha=arguments.head,
            token=arguments.token,
        )
    return attempt_supervisor_main(
        entrypoint=arguments.entrypoint,
        attempt_dir=arguments.attempt_dir,
        control_fd=arguments.control_fd,
        lease_fd=arguments.lease_fd,
        root_fd=arguments.root_fd,
        attempt_fd=arguments.attempt_fd,
        handoff_token=arguments.handoff_token,
    )


def _emit(value: dict[str, Any]) -> None:
    envelope = {
        **value,
        "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
        "named_lane_eligible": NAMED_LANE_ELIGIBLE,
    }
    serialized = canonical_json(envelope).decode("ascii")
    sys.stdout.write(serialized)


def _failure_payload(error: BaseException) -> dict[str, Any]:
    if isinstance(error, SupervisorError):
        failure = error.failure
        return {
            "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
            "named_lane_eligible": NAMED_LANE_ELIGIBLE,
            "overall_status": failure.status,
            "review_status": failure.review_status,
            "failure_stage": failure.stage,
            "failure_code": failure.code,
            "message": failure.message,
        }
    return {
        "review_contract": LOW_LEVEL_HELPER_REVIEW_CONTRACT,
        "named_lane_eligible": NAMED_LANE_ELIGIBLE,
        "overall_status": "inconclusive",
        "review_status": "not-run",
        "failure_stage": "cli",
        "failure_code": "cli-failed",
        "message": f"{type(error).__name__}: {error}",
    }


def main(
    argv: Sequence[str] | None = None, *, entrypoint: pathlib.Path | None = None
) -> int:
    require_python_313()
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    values = tuple(sys.argv[1:] if argv is None else argv)
    if values and values[0].startswith("_"):
        return _run_internal(values[0], values[1:])
    parser = _public_parser()
    arguments = parser.parse_args(values)
    executable = (entrypoint or pathlib.Path(sys.argv[0])).resolve(strict=True)
    try:
        if arguments.command == "preflight":
            result = preflight(
                helper_state=arguments.helper_state,
                repo=arguments.repo,
                base_sha=arguments.base_sha,
                head_sha=arguments.head_sha,
                pr_url=arguments.pr_url,
                retention_root=arguments.retention_root,
                checkout_parent=arguments.checkout_parent,
                git_executable=arguments.git_executable,
                codex_executable=arguments.codex_executable,
            )
            exit_code = 0
        elif arguments.command == "run":
            exit_code, result = run(
                entrypoint=executable,
                helper_state=arguments.helper_state,
                repo=arguments.repo,
                base_sha=arguments.base_sha,
                head_sha=arguments.head_sha,
                pr_url=arguments.pr_url,
                retention_root=arguments.retention_root,
                checkout_parent=arguments.checkout_parent,
                git_executable=arguments.git_executable,
                codex_executable=arguments.codex_executable,
            )
        elif arguments.command == "status":
            result = status(
                retention_root=arguments.retention_root,
                attempt_dir=arguments.attempt_dir,
            )
            exit_code = 0
        elif arguments.command == "final":
            result = final_result(
                retention_root=arguments.retention_root,
                attempt_dir=arguments.attempt_dir,
            )
            exit_code = 0
        elif arguments.command == "recover":
            exit_code, result = recover(
                entrypoint=executable,
                retention_root=arguments.retention_root,
                attempt_dir=arguments.attempt_dir,
            )
        elif arguments.command == "release":
            exit_code, result = release(
                entrypoint=executable,
                retention_root=arguments.retention_root,
                attempt_dir=arguments.attempt_dir,
                reason=arguments.reason,
            )
        else:
            exit_code, result = cleanup(
                entrypoint=executable,
                retention_root=arguments.retention_root,
                attempt_dir=arguments.attempt_dir,
            )
        _emit(result)
        return exit_code
    except BaseException as error:
        _emit(_failure_payload(error))
        return 2
