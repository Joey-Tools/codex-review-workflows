from __future__ import annotations

import argparse
import json
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
from .state import final, status
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
    secret_admission,
    validate_authoring_catalog_scanner_contract,
)


# Kept as non-dispatched compatibility code while old retained artifacts age out.
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
        help=(
            "Optional supplemental prompt template supporting review placeholders; "
            "it cannot replace the helper's mandatory review boundary."
        ),
    )
    parser.add_argument(
        "--keep-workspace",
        action="store_true",
        help="Keep the detached review workspace after completion.",
    )
    parser.add_argument(
        "--include-source-wip",
        action="store_true",
        help=(
            "Review a helper-private snapshot of source HEAD plus staged, "
            "unstaged, and nonignored untracked content. Review-only; not "
            "formal PR-readiness or merge-ready evidence."
        ),
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


PUBLIC_COMMANDS = ("synthetic-tokens", "secret-admission", "stateful")
RECOVERY_ONLY_STATEFUL_ACTIONS = ("status", "final", "cleanup")
RETIRED_STATEFUL_ACTIONS = ("start", "wait", "admission")
RETIRED_REVIEW_MESSAGE = (
    "the supplied-diff foreground and stateful review entrypoints were retired; "
    "use the review-orchestration-playbook named local lane and its clean-workspace "
    "helper instead. Only stateful status/final/cleanup remain as recovery-only "
    "migration routes for compatible pre-upgrade artifacts. Retained "
    "isolated_review commands: " + ", ".join(PUBLIC_COMMANDS)
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="isolated_review",
        description=(
            "Retained low-level utilities for exact-secret admission and approved "
            "synthetic-token fixtures, plus recovery-only inspection and cleanup "
            "of compatible pre-upgrade state. Review execution moved to the "
            "review-orchestration-playbook named local lanes."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "synthetic-tokens",
        add_help=False,
        help="Validate, list, or audit approved synthetic-token fixtures.",
    )
    commands.add_parser(
        "secret-admission",
        add_help=False,
        help="Run exact-secret admission without starting a reviewer.",
    )
    commands.add_parser(
        "stateful",
        add_help=False,
        help="Recover compatible pre-upgrade helper state; cannot start a review.",
    )
    return parser


def _build_stateful_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="isolated_review stateful",
        description=(
            "Recovery-only migration routes for compatible pre-upgrade helper "
            "state. These commands cannot start, resume, or wait on a reviewer "
            "and never satisfy a named lane."
        ),
    )
    actions = parser.add_subparsers(dest="action", required=True)
    for action in RECOVERY_ONLY_STATEFUL_ACTIONS:
        action_parser = actions.add_parser(action)
        action_parser.add_argument("--state-dir", required=True)
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


def _build_secret_admission_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="isolated_review secret-admission")
    parser.add_argument("--repo", default=".", help="Source Git repository.")
    parser.add_argument("--base-ref", required=True, help="Frozen base commit-ish.")
    parser.add_argument("--head-ref", required=True, help="Frozen head commit-ish.")
    parser.add_argument(
        "--synthetic-secret-exemption",
        action="append",
        default=[],
        help=(
            "Deprecated repeatable compatibility option. Every ID must name a "
            "catalog legacy exemption, but selection does not change exact-secret "
            "admission."
        ),
    )
    return parser


def _run_secret_admission(argv: list[str]) -> int:
    args = _build_secret_admission_parser().parse_args(argv)
    exit_code, summary = secret_admission(
        repo=pathlib.Path(args.repo),
        base_ref=args.base_ref,
        head_ref=args.head_ref,
        synthetic_secret_exemptions=tuple(args.synthetic_secret_exemption),
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return exit_code


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
            include_source_wip=bool(getattr(args, "include_source_wip", False)),
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


def _run_stateful(argv: list[str]) -> int:
    args = _build_stateful_parser().parse_args(argv)
    state_dir = pathlib.Path(args.state_dir)
    if args.action == "status":
        print(json.dumps(status(state_dir), indent=2, sort_keys=True))
        return 0
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
    try:
        if arguments and arguments[0] == "synthetic-tokens":
            return _run_synthetic_tokens(arguments[1:])
        if arguments and arguments[0] == "secret-admission":
            return _run_secret_admission(arguments[1:])
        if arguments and arguments[0] == "stateful":
            if len(arguments) > 1 and arguments[1] in RETIRED_STATEFUL_ACTIONS:
                raise ReviewError(RETIRED_REVIEW_MESSAGE)
            return _run_stateful(arguments[1:])
        if arguments and (
            arguments[0] == "_run-state"
            or (arguments[0].startswith("-") and arguments[0] not in {"-h", "--help"})
        ):
            raise ReviewError(RETIRED_REVIEW_MESSAGE)
        _build_parser().parse_args(arguments)
        raise AssertionError("top-level parser unexpectedly returned")
    except ForwardedSignal as error:
        if error.detail:
            print(f"error: {error.detail}", file=sys.stderr)
        return 128 + int(error.signum)
    except ReviewError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
