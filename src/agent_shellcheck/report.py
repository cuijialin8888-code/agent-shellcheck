from __future__ import annotations

import html
import json
import os
from pathlib import Path
from typing import Any

from .models import Finding, ScanResult
from .rules import iter_rules


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def render_report(result: ScanResult, output_format: str, version: str) -> str:
    renderers = {
        "text": render_text,
        "json": render_json,
        "sarif": render_sarif,
        "markdown": render_markdown,
        "html": render_html,
        "github": render_github,
    }
    try:
        renderer = renderers[output_format]
    except KeyError as exc:
        raise ValueError(f"unknown output format: {output_format}") from exc
    return renderer(result, version)


def render_text(result: ScanResult, version: str) -> str:
    del version
    lines: list[str] = []
    for finding in sorted(result.findings, key=Finding.sort_key):
        lines.append(
            f"{finding.relative_path}:{finding.line}:{finding.column}  "
            f"{finding.rule_id}  {finding.severity.label}  {finding.message}"
        )
        lines.append(f"  evidence: {finding.evidence}")
        lines.append(f"  help: {finding.help or finding.rule.help}")
    counts = result.counts()
    if lines:
        lines.append("")
    lines.append(
        f"{counts['error']} errors, {counts['warning']} warnings, {counts['info']} info "
        f"in {result.files_scanned} {_plural(result.files_scanned, 'file')}"
    )
    return "\n".join(lines) + "\n"


def render_json(result: ScanResult, version: str) -> str:
    return json.dumps(result.to_dict(version), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def render_sarif(result: ScanResult, version: str) -> str:
    findings = sorted(result.findings, key=Finding.sort_key)
    used_rule_ids = {finding.rule_id for finding in findings}
    rules = []
    for rule in iter_rules(used_rule_ids):
        rules.append(
            {
                "id": rule.rule_id,
                "name": rule.title.replace(" ", ""),
                "shortDescription": {"text": rule.summary},
                "fullDescription": {"text": rule.help},
                "defaultConfiguration": {"level": _sarif_level(rule.default_severity.label)},
                "help": {
                    "text": rule.help,
                    "markdown": _rule_help_markdown(rule),
                },
                "properties": {
                    "affectedShells": list(rule.affected_shells),
                    "references": list(rule.references),
                },
            }
        )

    results: list[dict[str, Any]] = []
    for finding in findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity.label),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.relative_path.replace("\\", "/")},
                            "region": {
                                "startLine": finding.line,
                                "startColumn": finding.column,
                            },
                        }
                    }
                ],
                "properties": {
                    "evidence": finding.evidence,
                    "help": finding.help or finding.rule.help,
                    **finding.properties,
                },
            }
        )

    payload = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-shellcheck",
                        "informationUri": "https://github.com/cuijialin8888-code/agent-shellcheck",
                        "semanticVersion": version,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def render_markdown(result: ScanResult, version: str) -> str:
    del version
    counts = result.counts()
    lines = [
        "# agent-shellcheck report",
        "",
        f"Scanned **{result.files_scanned}** {_plural(result.files_scanned, 'file')} "
        f"for target **{_escape_markdown(result.target)}**.",
        "",
        f"**{counts['error']} errors · {counts['warning']} warnings · {counts['info']} info**",
        "",
    ]
    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    lines.extend(
        [
            "| Location | Rule | Severity | Message |",
            "|---|---|---|---|",
        ]
    )
    for finding in sorted(result.findings, key=Finding.sort_key):
        location = f"{finding.relative_path}:{finding.line}:{finding.column}"
        lines.append(
            f"| `{_escape_markdown(location)}` | `{finding.rule_id}` | "
            f"{finding.severity.label} | {_escape_markdown(finding.message)} |"
        )
    return "\n".join(lines) + "\n"


def render_html(result: ScanResult, version: str) -> str:
    counts = result.counts()
    rows = []
    for finding in sorted(result.findings, key=Finding.sort_key):
        location = f"{finding.relative_path}:{finding.line}:{finding.column}"
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(location)}</code></td>"
            f"<td><code>{html.escape(finding.rule_id)}</code></td>"
            f"<td><span class=\"{finding.severity.label}\">{finding.severity.label}</span></td>"
            f"<td>{html.escape(finding.message)}<details><summary>Evidence</summary>"
            f"<pre>{html.escape(finding.evidence)}</pre><p>{html.escape(finding.help or finding.rule.help)}</p>"
            "</details></td></tr>"
        )
    body = "".join(rows) or '<tr><td colspan="4">No findings.</td></tr>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>agent-shellcheck report</title><style>
body{{font:15px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#172033}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #d7deea;padding:.6rem;text-align:left;vertical-align:top}}
th{{background:#f4f7fb}}code,pre{{font-family:ui-monospace,monospace}}.error{{color:#b42318}}.warning{{color:#935f00}}.info{{color:#175cd3}}
small{{color:#667085}}</style></head><body><h1>agent-shellcheck report</h1>
<p><strong>{counts['error']} errors · {counts['warning']} warnings · {counts['info']} info</strong></p>
<p>Scanned {result.files_scanned} {_plural(result.files_scanned, 'file')} for target <code>{html.escape(result.target)}</code>.</p>
<table><thead><tr><th>Location</th><th>Rule</th><th>Severity</th><th>Finding</th></tr></thead><tbody>{body}</tbody></table>
<p><small>Generated by agent-shellcheck {html.escape(version)}. Self-contained; no remote assets or scripts.</small></p>
</body></html>\n"""


def render_github(result: ScanResult, version: str) -> str:
    del version
    lines: list[str] = []
    levels = {"error": "error", "warning": "warning", "info": "notice"}
    for finding in sorted(result.findings, key=Finding.sort_key):
        properties = (
            f"file={_github_property(_github_path(result, finding))},"
            f"line={finding.line},col={finding.column},title={_github_property(finding.rule_id)}"
        )
        message = f"{finding.rule_id}: {finding.message} Evidence: {finding.evidence}"
        lines.append(f"::{levels[finding.severity.label]} {properties}::{_github_data(message)}")
    counts = result.counts()
    lines.append(
        f"agent-shellcheck: {counts['error']} {_plural(counts['error'], 'error')}, "
        f"{counts['warning']} {_plural(counts['warning'], 'warning')}, "
        f"{counts['info']} info in {result.files_scanned} {_plural(result.files_scanned, 'file')}"
    )
    return "\n".join(lines) + "\n"


def _sarif_level(severity: str) -> str:
    return {"error": "error", "warning": "warning", "info": "note"}[severity]


def _rule_help_markdown(rule) -> str:
    lines = [rule.help]
    if rule.references:
        lines.append("References: " + ", ".join(rule.references))
    return "\n\n".join(lines)


def _escape_markdown(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _github_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _github_path(result: ScanResult, finding: Finding) -> str:
    absolute = (result.root / Path(finding.relative_path)).resolve()
    for workspace in _github_workspace_roots():
        try:
            return absolute.relative_to(workspace).as_posix()
        except ValueError:
            continue
    return finding.relative_path.replace("\\", "/")


def _github_workspace_roots() -> tuple[Path, ...]:
    candidates: list[Path] = []
    configured = os.environ.get("GITHUB_WORKSPACE")
    if configured:
        candidates.append(Path(configured).expanduser().resolve())

    current = Path.cwd().resolve()
    repository_root: Path | None = None
    search = current
    while True:
        if (search / ".git").exists():
            repository_root = search
            break
        if search.parent == search:
            break
        search = search.parent

    if repository_root is not None:
        candidates.append(repository_root)
    candidates.append(current)
    return tuple(dict.fromkeys(candidates))


def _github_property(value: str) -> str:
    return _github_data(value).replace(":", "%3A").replace(",", "%2C")


def _plural(count: int, noun: str) -> str:
    return noun if count == 1 else noun + "s"
