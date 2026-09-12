from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .config import (
    DEFAULT_FAIL_ON,
    DEFAULT_MAX_FILES,
    DEFAULT_MIN_SEVERITY,
    DEFAULT_TARGET,
    ConfigError,
    ProjectConfig,
    load_project_config,
)
from .discover import DiscoveryError
from .models import Severity
from .report import render_report
from .rules import RULE_BY_ID, TARGETS
from .scanner import scan_paths


FORMATS = ("text", "json", "sarif", "markdown", "html", "github")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-shellcheck",
        description="Catch cross-shell portability bugs in agent instruction files.",
    )
    parser.add_argument("paths", nargs="*", metavar="PATH", help="instruction file or directory (default: .)")
    parser.add_argument("--target", choices=TARGETS, help="target for generic command snippets")
    parser.add_argument("--format", choices=FORMATS, default="text", dest="output_format", help="report format")
    parser.add_argument("--output", type=Path, help="write the report to this file")
    parser.add_argument(
        "--min-severity",
        choices=("info", "warning", "error"),
        help="lowest severity to include (default: info)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none", "info", "warning", "error"),
        help="lowest severity that returns status 1 (default: error)",
    )
    parser.add_argument("--ignore", action="append", metavar="RULE_ID", help="ignore a rule ID; repeatable")
    parser.add_argument("--exclude", action="append", metavar="GLOB", help="exclude a discovery glob; repeatable")
    parser.add_argument("--max-files", type=_positive_int, metavar="NUMBER", help="maximum discovered files")
    config_group = parser.add_mutually_exclusive_group()
    config_group.add_argument("--config", type=Path, metavar="PATH", help="use an explicit JSON policy file")
    config_group.add_argument("--no-config", action="store_true", help="do not discover .agent-shellcheck.json")
    parser.add_argument("--show-config", action="store_true", help="print the effective policy as JSON and exit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_project_config(explicit=args.config, disabled=args.no_config)
    except ConfigError as exc:
        parser.error(str(exc))

    unknown_config_rules = set(config.ignore).difference(RULE_BY_ID)
    if unknown_config_rules:
        parser.error("unknown rule ID in configuration: " + ", ".join(sorted(unknown_config_rules)))

    try:
        effective = _effective_policy(args, config)
    except ConfigError as exc:
        parser.error(str(exc))
    ignored = _normalize_ignored(effective["ignore"])
    unknown = ignored.difference(RULE_BY_ID)
    if unknown:
        parser.error("unknown rule ID: " + ", ".join(sorted(unknown)))

    if args.show_config:
        sys.stdout.write(json.dumps(effective, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        return 0

    try:
        result = scan_paths(
            effective["paths"],
            target=effective["target"],
            excludes=effective["exclude"],
            min_severity=Severity.parse(effective["minSeverity"]),
            ignore_rules=ignored,
            max_files=effective["maxFiles"],
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

    if effective["failOn"] == "none":
        return 0
    threshold = Severity.parse(effective["failOn"])
    return 1 if result.has_findings_at_or_above(threshold) else 0


def _effective_policy(args: argparse.Namespace, config: ProjectConfig) -> dict[str, object]:
    if args.paths:
        paths = [Path(value).expanduser() for value in args.paths]
    elif config.paths:
        paths = config.resolved_paths()
    else:
        paths = [Path.cwd()]
    return {
        "configFile": str(config.source) if config.source is not None else None,
        "paths": [str(path) for path in paths],
        "target": args.target or config.target or DEFAULT_TARGET,
        "minSeverity": args.min_severity or config.min_severity or DEFAULT_MIN_SEVERITY,
        "failOn": args.fail_on or config.fail_on or DEFAULT_FAIL_ON,
        "ignore": list(args.ignore if args.ignore is not None else config.ignore),
        "exclude": list(args.exclude if args.exclude is not None else config.exclude),
        "maxFiles": args.max_files or config.max_files or DEFAULT_MAX_FILES,
    }


def _normalize_ignored(values: list[str] | tuple[str, ...]) -> set[str]:
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
