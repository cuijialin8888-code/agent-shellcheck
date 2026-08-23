from __future__ import annotations

import argparse
from pathlib import Path
import sys

from . import __version__
from .discover import DiscoveryError
from .models import Severity
from .report import render_report
from .rules import RULE_BY_ID, TARGETS
from .scanner import scan_paths


FORMATS = ("text", "json", "sarif", "markdown", "html")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-shellcheck",
        description="Catch cross-shell portability bugs in agent instruction files.",
    )
    parser.add_argument("paths", nargs="*", metavar="PATH", help="instruction file or directory (default: .)")
    parser.add_argument("--target", choices=TARGETS, default="auto", help="target for generic command snippets")
    parser.add_argument("--format", choices=FORMATS, default="text", dest="output_format", help="report format")
    parser.add_argument("--output", type=Path, help="write the report to this file")
    parser.add_argument(
        "--min-severity",
        choices=("info", "warning", "error"),
        default="info",
        help="lowest severity to include (default: info)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none", "info", "warning", "error"),
        default="error",
        help="lowest severity that returns status 1 (default: error)",
    )
    parser.add_argument("--ignore", action="append", default=[], metavar="RULE_ID", help="ignore a rule ID; repeatable")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="exclude a discovery glob; repeatable")
    parser.add_argument("--max-files", type=_positive_int, default=1000, metavar="NUMBER", help="maximum discovered files")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    ignored = _normalize_ignored(args.ignore)
    unknown = ignored.difference(RULE_BY_ID)
    if unknown:
        parser.error("unknown rule ID: " + ", ".join(sorted(unknown)))

    try:
        result = scan_paths(
            args.paths or [Path.cwd()],
            target=args.target,
            excludes=args.exclude,
            min_severity=Severity.parse(args.min_severity),
            ignore_rules=ignored,
            max_files=args.max_files,
        )
        report = render_report(result, args.output_format, __version__)
        if args.output:
            output = args.output.expanduser().resolve()
            if output in {path.resolve() for path in result.scanned_paths}:
                raise DiscoveryError("refusing to overwrite a scanned instruction file with the report")
            if not output.parent.is_dir():
                raise DiscoveryError(f"output directory does not exist: {output.parent}")
            with output.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(report)
        else:
            sys.stdout.write(report)
    except (DiscoveryError, OSError, ValueError) as exc:
        print(f"agent-shellcheck: {exc}", file=sys.stderr)
        return 2

    if args.fail_on == "none":
        return 0
    threshold = Severity.parse(args.fail_on)
    return 1 if any(finding.severity >= threshold for finding in result.findings) else 0


def _normalize_ignored(values: list[str]) -> set[str]:
    result: set[str] = set()
    for value in values:
        result.update(item.strip().upper() for item in value.split(",") if item.strip())
    return result


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
