from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any


class Severity(IntEnum):
    INFO = 1
    WARNING = 2
    ERROR = 3

    @classmethod
    def parse(cls, value: str) -> "Severity":
        normalized = value.strip().lower()
        mapping = {
            "info": cls.INFO,
            "warning": cls.WARNING,
            "error": cls.ERROR,
        }
        if normalized not in mapping:
            raise ValueError(f"unknown severity: {value}")
        return mapping[normalized]

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class CodeBlock:
    path: Path
    relative_path: str
    language: str
    dialect: str
    start_line: int
    end_line: int
    content_start_line: int
    lines: tuple[str, ...]
    heading: str | None = None
    closed: bool = True


@dataclass(frozen=True)
class CommandSnippet:
    path: Path
    relative_path: str
    line: int
    column: int
    text: str
    dialect: str
    source_kind: str
    heading: str | None = None


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    default_severity: Severity
    summary: str
    help: str
    affected_shells: tuple[str, ...]
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "title": self.title,
            "defaultSeverity": self.default_severity.label,
            "summary": self.summary,
            "help": self.help,
            "affectedShells": list(self.affected_shells),
            "references": list(self.references),
        }


@dataclass(frozen=True)
class Finding:
    rule: Rule
    severity: Severity
    relative_path: str
    line: int
    column: int
    message: str
    evidence: str
    help: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)

    @property
    def rule_id(self) -> str:
        return self.rule.rule_id

    def sort_key(self) -> tuple[str, int, int, str, str]:
        return (
            self.relative_path.casefold(),
            self.line,
            self.column,
            self.rule_id,
            self.evidence,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "severity": self.severity.label,
            "path": self.relative_path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "evidence": self.evidence,
            "help": self.help or self.rule.help,
            "affectedShells": list(self.rule.affected_shells),
            "properties": self.properties,
        }


@dataclass
class ScanResult:
    root: Path
    target: str
    files_scanned: int
    blocks_scanned: int
    snippets_scanned: int
    findings: list[Finding]
    skipped_files: int = 0
    scanned_paths: tuple[Path, ...] = ()

    def counts(self) -> dict[str, int]:
        counts = {"error": 0, "warning": 0, "info": 0}
        for finding in self.findings:
            counts[finding.severity.label] += 1
        return counts

    def to_dict(self, version: str) -> dict[str, Any]:
        ordered = sorted(self.findings, key=Finding.sort_key)
        counts = self.counts()
        return {
            "schemaVersion": 1,
            "tool": {"name": "agent-shellcheck", "version": version},
            "root": str(self.root),
            "target": self.target,
            "summary": {
                "filesScanned": self.files_scanned,
                "blocksScanned": self.blocks_scanned,
                "snippetsScanned": self.snippets_scanned,
                "skippedFiles": self.skipped_files,
                "findingCount": len(ordered),
                **counts,
            },
            "findings": [finding.to_dict() for finding in ordered],
        }
