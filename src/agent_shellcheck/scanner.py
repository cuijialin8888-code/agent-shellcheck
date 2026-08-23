from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .discover import discover_files, read_text, relative_path
from .markdown import parse_markdown
from .models import Finding, ScanResult, Severity
from .rules import RULE_BY_ID, TARGETS, canonical_target, evaluate_snippet


def scan_paths(
    inputs: Iterable[str | Path],
    *,
    target: str = "auto",
    excludes: Iterable[str] = (),
    min_severity: Severity = Severity.INFO,
    ignore_rules: Iterable[str] = (),
    max_files: int = 1000,
) -> ScanResult:
    if target not in TARGETS:
        raise ValueError(f"unknown target: {target}")
    if not isinstance(min_severity, Severity):
        min_severity = Severity.parse(str(min_severity))
    if max_files < 1:
        raise ValueError("max_files must be at least 1")

    ignored = {value.upper() for value in ignore_rules}
    unknown_ignored = ignored.difference(RULE_BY_ID)
    if unknown_ignored:
        rendered = ", ".join(sorted(unknown_ignored))
        raise ValueError(f"unknown rule ID: {rendered}")

    discovery = discover_files(inputs, excludes=excludes, max_files=max_files)
    findings: list[Finding] = []
    block_count = 0
    snippet_count = 0

    for path in discovery.files:
        relative = relative_path(path, discovery.root)
        blocks, snippets = parse_markdown(path, relative, read_text(path))
        block_count += len(blocks)
        snippet_count += len(snippets)

        for block in blocks:
            if block.closed or "ASC000" in ignored:
                continue
            finding = Finding(
                rule=RULE_BY_ID["ASC000"],
                severity=Severity.ERROR,
                relative_path=relative,
                line=block.start_line,
                column=1,
                message="Markdown command fence is not closed before end of file",
                evidence=f"```{block.language}" if block.language else "```",
                properties={
                    "declaredDialect": block.dialect,
                    "resolvedTarget": canonical_target(target),
                },
            )
            if finding.severity >= min_severity:
                findings.append(finding)

        for snippet in snippets:
            for finding in evaluate_snippet(snippet, target):
                if finding.rule_id in ignored or finding.severity < min_severity:
                    continue
                findings.append(finding)

    findings.sort(key=Finding.sort_key)
    return ScanResult(
        root=discovery.root,
        target=canonical_target(target),
        files_scanned=len(discovery.files),
        blocks_scanned=block_count,
        snippets_scanned=snippet_count,
        findings=findings,
        skipped_files=discovery.skipped_files,
        scanned_paths=discovery.files,
    )
