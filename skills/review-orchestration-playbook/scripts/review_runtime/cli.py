from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .common import ReviewError
from .providers import CLAUDE_EGRESS_CONSENTS, run_review
from .state import final, run_state, start, status, wait
from .workspace import cleanup_workspace, prepare_workspace


def _add_review_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo", default=".", help="Source Git repository.")
    parser.add_argument(
        "--reviewer",
        choices=("codex", "claude"),
        default="codex",
        help="Logical local reviewer lane.",
    )
    parser.add_argument("--base-ref", required=True, help="Frozen base commit-ish.")
    parser.add_argument("--head-ref", required=True, help="Frozen head commit-ish.")
    parser.add_argument(
        "--prompt-file",
        help="Optional prompt template supporting review placeholders.",
    )
    parser.add_argument(
        "--keep-workspace",
        action="store_true",
        help="Keep the detached review workspace after completion.",
    )
    parser.add_argument(
        "--egress-consent",
        choices=CLAUDE_EGRESS_CONSENTS,
        help=(
            "Required for the Claude-family lane; records the user's explicit "
            "external-review authorization."
        ),
    )


def _validate_review_arguments(args: argparse.Namespace) -> None:
    if args.reviewer == "claude" and args.egress_consent is None:
        raise ReviewError(
            "--reviewer claude requires --egress-consent with the explicit user authorization"
        )
    if args.reviewer != "claude" and args.egress_consent is not None:
        raise ReviewError("--egress-consent is valid only with --reviewer claude")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="isolated_review",
        description=(
            "Run a pinned Codex or Claude-family reviewer against one frozen Git range "
            "inside a detached read-only review workspace."
        ),
    )
    _add_review_arguments(parser)
    return parser


def _build_stateful_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="isolated_review stateful")
    actions = parser.add_subparsers(dest="action", required=True)
    start_parser = actions.add_parser("start")
    _add_review_arguments(start_parser)
    for action in ("status", "final"):
        action_parser = actions.add_parser(action)
        action_parser.add_argument("--state-dir", required=True)
    wait_parser = actions.add_parser("wait")
    wait_parser.add_argument("--state-dir", required=True)
    wait_parser.add_argument("--timeout-seconds", type=float)
    return parser


def _shim_source(script_path: pathlib.Path) -> pathlib.Path:
    return script_path.resolve().with_name("git_readonly_shim")


def _run_foreground(args: argparse.Namespace, *, script_path: pathlib.Path) -> int:
    _validate_review_arguments(args)
    review = prepare_workspace(
        repo=pathlib.Path(args.repo),
        base_ref=args.base_ref,
        head_ref=args.head_ref,
        prompt_override=pathlib.Path(args.prompt_file) if args.prompt_file else None,
    )
    try:
        outcome = run_review(
            review=review,
            reviewer=args.reviewer,
            shim_source=_shim_source(script_path),
            egress_consent=args.egress_consent,
        )
        if outcome.final_text:
            print(outcome.final_text)
        elif (review.container_dir / "runner-error.txt").is_file():
            print(
                (review.container_dir / "runner-error.txt")
                .read_text(encoding="utf-8", errors="replace")
                .strip(),
                file=sys.stderr,
            )
        else:
            print(
                f"review failed; evidence retained at {review.container_dir}",
                file=sys.stderr,
            )
        return outcome.returncode
    finally:
        if args.keep_workspace:
            print(f"kept review workspace: {review.container_dir}", file=sys.stderr)
        elif (review.container_dir / "final.txt").is_file():
            cleanup_workspace(review, keep_container=False)
        else:
            cleanup_workspace(review, keep_container=True)


def _run_stateful(argv: list[str], *, script_path: pathlib.Path) -> int:
    args = _build_stateful_parser().parse_args(argv)
    state_dir = pathlib.Path(getattr(args, "state_dir", "."))
    if args.action == "start":
        _validate_review_arguments(args)
        created = start(
            script_path=script_path,
            repo=pathlib.Path(args.repo),
            reviewer=args.reviewer,
            base_ref=args.base_ref,
            head_ref=args.head_ref,
            prompt_file=pathlib.Path(args.prompt_file) if args.prompt_file else None,
            keep_workspace=args.keep_workspace,
            egress_consent=args.egress_consent,
        )
        print(created)
        return 0
    if args.action == "status":
        print(json.dumps(status(state_dir), indent=2, sort_keys=True))
        return 0
    if args.action == "wait":
        return wait(state_dir, timeout_seconds=args.timeout_seconds)
    if args.action == "final":
        exit_code, text = final(state_dir)
        print(text, file=sys.stdout if exit_code == 0 else sys.stderr)
        return exit_code
    raise ReviewError(f"unknown stateful action: {args.action}")


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    script_path = pathlib.Path(sys.argv[0]).resolve()
    try:
        if arguments and arguments[0] == "_run-state":
            internal = argparse.ArgumentParser(add_help=False)
            internal.add_argument("action")
            internal.add_argument("--state-dir", required=True)
            parsed = internal.parse_args(arguments)
            return run_state(
                state_dir=pathlib.Path(parsed.state_dir),
                shim_source=_shim_source(script_path),
            )
        if arguments and arguments[0] == "stateful":
            return _run_stateful(arguments[1:], script_path=script_path)
        return _run_foreground(
            _build_parser().parse_args(arguments), script_path=script_path
        )
    except ReviewError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
