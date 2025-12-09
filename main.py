#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from getpass import getpass

from password_generator import generate_password
from password_checker import check_password_strength, PasswordReport


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password-tool",
        description="Educational CLI tool for password generation and strength checking.",
    )

    subparsers = parser.add_subparsers(
        title="subcommands",
        dest="command",
        required=True,
        help="Available commands",
    )

    # generate subcommand
    gen_parser = subparsers.add_parser(
        "generate",
        help="Generate a random password.",
        description="Generate a random password using cryptographically secure randomness.",
    )
    gen_parser.add_argument(
        "--length",
        type=int,
        default=16,
        help="Password length (default: 16).",
    )
    gen_parser.add_argument(
        "--lower",
        type=lambda v: v.lower() == "true",
        default=True,
        help="Use lowercase letters (True/False, default: True).",
    )
    gen_parser.add_argument(
        "--upper",
        type=lambda v: v.lower() == "true",
        default=True,
        help="Use uppercase letters (True/False, default: True).",
    )
    gen_parser.add_argument(
        "--digits",
        type=lambda v: v.lower() == "true",
        default=True,
        help="Use digits (True/False, default: True).",
    )
    gen_parser.add_argument(
        "--symbols",
        type=lambda v: v.lower() == "true",
        default=True,
        help="Use special symbols (True/False, default: True).",
    )
    gen_parser.set_defaults(func=handle_generate)

    # check subcommand
    check_parser = subparsers.add_parser(
        "check",
        help="Check password strength.",
        description=(
            "Check strength of a password and get a score, category and basic recommendations."
        ),
    )
    check_parser.add_argument(
        "--password",
        type=str,
        help="Password to check. If omitted, will be requested via hidden input.",
    )
    check_parser.set_defaults(func=handle_check)

    return parser


def handle_generate(args: argparse.Namespace) -> int:
    if not any([args.lower, args.upper, args.digits, args.symbols]):
        print("Error: at least one character class must be enabled.", file=sys.stderr)
        return 1

    try:
        password = generate_password(
            length=args.length,
            use_lower=args.lower,
            use_upper=args.upper,
            use_digits=args.digits,
            use_symbols=args.symbols,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(password)
    return 0


def handle_check(args: argparse.Namespace) -> int:
    password = args.password
    if password is None:
        # secure, non-echo input in supported terminals
        password = getpass("Enter password to check: ")

    report: PasswordReport = check_password_strength(password)

    print(f"Score: {report.score}/100")
    print(f"Category: {report.category}")
    if report.is_dictionary_like:
        print("Dictionary-like: yes (password looks like an obvious word/phrase)")
    else:
        print("Dictionary-like: no")
    if report.recommendations:
        print("Recommendations:")
        for rec in report.recommendations:
            print(f"- {rec}")

    return 0


def main() -> None:
    parser = create_parser()
    args = parser.parse_args()
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        raise SystemExit(1)
    exit_code = func(args)
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
