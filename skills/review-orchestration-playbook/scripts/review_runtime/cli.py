from __future__ import annotations

import argparse
import json
import os
import pathlib
import signal
import sys

from .common import (
    ForwardedSignal,
    ReviewError,
    block_forwarded_signals,
    consume_pending_forwarded_signal,
    forwarded_signals,
    restore_signal_mask,
)
from .providers import CLAUDE_EGRESS_CONSENTS, run_review
from .state import FINAL_CLEANUP_TIMEOUT_SECONDS, ReviewPreparationGuard
from .state import cleanup as cleanup_state
from .state import admission, final, run_state, start, status, wait
from .synthetic_tokens import (
    authoring_metadata,
    legacy_metadata,
    load_catalog,
)
from .workspace import (
    ReviewWorkspace,
    cleanup_workspace,
    prepare_workspace,
    remove_private_review_artifacts,
    validate_authoring_catalog_scanner_contract,
)


def _add_review_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo", default=".", help="Source Git repository.")
    parser.add_argument(
        "--reviewer",
        choices=("codex", "claude"),
        default="codex",
        help=(
            "Low-level supplied-diff helper reviewer; this does not satisfy "
            "a canonical named review shape."
        ),
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
            "Required for the low-level Claude helper; records explicit "
            "Anthropic-only consent or separately requested Anthropic-plus-Copilot "
            "compatibility-fallback consent."
        ),
    )
    parser.add_argument(
        "--synthetic-secret-exemption",
        action="append",
        default=[],
        help=(
            "Deprecated compatibility option. Known legacy IDs are validated, "
            "but selection no longer changes secret-delta admission."
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
            "Run a pinned Codex or low-level Claude helper against one frozen Git range "
            "inside a detached read-only review workspace. Results are diagnostic and "
            "ineligible for named review lanes; the foreground command prints only the "
            "raw helper artifact, so automation that needs machine metadata must use "
            "the stateful interface."
        ),
    )
    _add_review_arguments(parser)
    return parser


def _build_stateful_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="isolated_review stateful",
        description=(
            "Manage a low-level supplied-diff helper run; its status is always "
            "named_lane_eligible=false."
        ),
    )
    actions = parser.add_subparsers(dest="action", required=True)
    start_parser = actions.add_parser("start")
    _add_review_arguments(start_parser)
    for action in ("status", "final", "cleanup", "admission"):
        action_parser = actions.add_parser(action)
        action_parser.add_argument("--state-dir", required=True)
    wait_parser = actions.add_parser("wait")
    wait_parser.add_argument("--state-dir", required=True)
    wait_parser.add_argument("--timeout-seconds", type=float)
    return parser


def _build_synthetic_tokens_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="isolated_review synthetic-tokens")
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("validate")
    list_parser = actions.add_parser("list")
    list_parser.add_argument("--json", action="store_true")
    get_parser = actions.add_parser("get")
    get_parser.add_argument("id")
    get_parser.add_argument("--json", action="store_true")
    exemptions_parser = actions.add_parser("list-exemptions")
    exemptions_parser.add_argument("--json", action="store_true")
    audit_parser = actions.add_parser("audit-master")
    audit_parser.add_argument("--repo", required=True)
    audit_parser.add_argument("--ref", required=True)
    audit_parser.add_argument("--exemption", required=True)
    return parser


def _run_synthetic_tokens(argv: list[str]) -> int:
    args = _build_synthetic_tokens_parser().parse_args(argv)
    catalog = load_catalog()
    validate_authoring_catalog_scanner_contract(catalog)
    if args.action == "validate":
        print(
            json.dumps(
                {
                    "pool_version": catalog.pool_version,
                    "schema_version": catalog.schema_version,
                    "status": "valid",
                },
                sort_keys=True,
            )
        )
        return 0
    if args.action == "list":
        payload = {
            "pool_version": catalog.pool_version,
            "tokens": authoring_metadata(catalog),
        }
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            for token in payload["tokens"]:
                print(
                    f"{token['id']}\t{token['role']}\t{token['state']}\t{token['rule']}"
                )
        return 0
    if args.action == "get":
        token = catalog.authoring_token(args.id)
        payload = {
            "pool_version": catalog.pool_version,
            "token": {
                "id": token.identifier,
                "role": token.role,
                "rule": token.rule,
                "state": token.state,
                "value": token.value.decode("ascii"),
                "value_sha256": token.value_sha256,
            },
        }
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(payload["token"]["value"])
        return 0
    if args.action == "list-exemptions":
        payload = {
            "exemptions": legacy_metadata(catalog),
            "pool_version": catalog.pool_version,
        }
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            for exemption in payload["exemptions"]:
                print(
                    f"{exemption['id']}\t{exemption['repository']}\t"
                    f"{len(exemption['values'])}"
                )
        return 0
    if args.action == "audit-master":
        from .workspace import audit_legacy_exemption

        evidence = audit_legacy_exemption(
            repo=pathlib.Path(args.repo),
            ref=args.ref,
            exemption=catalog.legacy_exemption(args.exemption),
        )
        print(json.dumps(evidence, indent=2, sort_keys=True))
        return 0
    raise ReviewError(f"unknown synthetic-tokens action: {args.action}")


def _run_foreground(args: argparse.Namespace) -> int:
    preparation_guard = ReviewPreparationGuard()
    _validate_review_arguments(args)
    review = None
    returncode = 1
    cleanup_error: str | None = None

    def forward_signal(signum: int, _frame) -> None:
        raise ForwardedSignal(signum)

    previous_handlers = {
        signum: signal.signal(signum, forward_signal) for signum in forwarded_signals()
    }

    def accept_workspace(prepared: ReviewWorkspace) -> None:
        nonlocal review
        preparation_guard.accept_workspace(prepared)
        review = preparation_guard.require_review()

    try:
        prepare_workspace(
            repo=pathlib.Path(args.repo),
            base_ref=args.base_ref,
            head_ref=args.head_ref,
            ownership_handoff=accept_workspace,
            preparation_cleanup_handoff=(preparation_guard.accept_preparation_cleanup),
            synthetic_secret_exemptions=tuple(
                getattr(args, "synthetic_secret_exemption", ())
            ),
            prompt_override=(
                pathlib.Path(args.prompt_file) if args.prompt_file else None
            ),
        )
        if review is None:
            raise ReviewError("workspace ownership handoff did not complete")
        outcome = run_review(
            review=review,
            reviewer=args.reviewer,
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
        returncode = outcome.returncode
    finally:
        previous_mask = block_forwarded_signals()
        pending_signal: signal.Signals | None = None
        try:
            if review is not None:
                cleanup_error = preparation_guard.acquire_final_cleanup_lock()
                if cleanup_error is None:
                    if args.keep_workspace:
                        cleanup_error = remove_private_review_artifacts(
                            review.container_dir,
                            expected=review.private_cleanup,
                        )
                        print(
                            f"kept review workspace: {review.container_dir}",
                            file=sys.stderr,
                        )
                    elif (review.container_dir / "final.txt").is_file():
                        cleanup_error = cleanup_workspace(review, keep_container=False)
                    else:
                        cleanup_error = cleanup_workspace(review, keep_container=True)
                if cleanup_error:
                    print(
                        "review cleanup failed; evidence may remain near "
                        f"{review.container_dir}; inspect cleanup state: "
                        f"{cleanup_error}",
                        file=sys.stderr,
                    )
            pending_signal = consume_pending_forwarded_signal()
        finally:
            try:
                preparation_guard.close()
            finally:
                restore_signal_mask(previous_mask)
                for signum, previous_handler in previous_handlers.items():
                    signal.signal(signum, previous_handler)
        if pending_signal is not None:
            raise ForwardedSignal(pending_signal)
    return 1 if cleanup_error and returncode == 0 else returncode


def _run_stateful(argv: list[str], *, script_path: pathlib.Path) -> int:
    args = _build_stateful_parser().parse_args(argv)
    state_dir = pathlib.Path(getattr(args, "state_dir", "."))
    if args.action == "start":
        _validate_review_arguments(args)
        start(
            script_path=script_path,
            repo=pathlib.Path(args.repo),
            reviewer=args.reviewer,
            base_ref=args.base_ref,
            head_ref=args.head_ref,
            prompt_file=pathlib.Path(args.prompt_file) if args.prompt_file else None,
            keep_workspace=args.keep_workspace,
            egress_consent=args.egress_consent,
            synthetic_secret_exemptions=tuple(
                getattr(args, "synthetic_secret_exemption", ())
            ),
            publisher=lambda created: print(created, flush=True),
        )
        return 0
    if args.action == "status":
        print(json.dumps(status(state_dir), indent=2, sort_keys=True))
        return 0
    if args.action == "admission":
        exit_code, summary = admission(state_dir)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return exit_code
    if args.action == "wait":
        return wait(state_dir, timeout_seconds=args.timeout_seconds)
    if args.action == "final":
        exit_code, text = final(state_dir)
        print(text, file=sys.stdout if exit_code == 0 else sys.stderr)
        return exit_code
    if args.action == "cleanup":
        return cleanup_state(
            state_dir,
            timeout_seconds=FINAL_CLEANUP_TIMEOUT_SECONDS,
        )
    raise ReviewError(f"unknown stateful action: {args.action}")


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    script_path = pathlib.Path(sys.argv[0]).resolve()
    try:
        if arguments and arguments[0] == "_run-state":
            internal = argparse.ArgumentParser(add_help=False)
            internal.add_argument("action")
            internal.add_argument("--state-dir", required=True)
            internal.add_argument("--lock-fd", required=True, type=int)
            internal.add_argument(
                "--reviewer",
                required=True,
                choices=("codex", "claude"),
            )
            internal.add_argument(
                "--egress-consent",
                choices=CLAUDE_EGRESS_CONSENTS,
            )
            parsed = internal.parse_args(arguments)
            _validate_review_arguments(parsed)
            exit_code = run_state(
                state_dir=pathlib.Path(parsed.state_dir),
                lock_fd=parsed.lock_fd,
                terminal_process=True,
                expected_reviewer=parsed.reviewer,
                expected_egress_consent=parsed.egress_consent,
            )
            os._exit(exit_code)
        if arguments and arguments[0] == "stateful":
            return _run_stateful(arguments[1:], script_path=script_path)
        if arguments and arguments[0] == "synthetic-tokens":
            return _run_synthetic_tokens(arguments[1:])
        return _run_foreground(_build_parser().parse_args(arguments))
    except ForwardedSignal as error:
        if error.detail:
            print(f"error: {error.detail}", file=sys.stderr)
        return 128 + int(error.signum)
    except ReviewError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
