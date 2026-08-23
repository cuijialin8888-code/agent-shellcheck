from __future__ import annotations

import re
from pathlib import Path

from .models import CodeBlock, CommandSnippet


FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})\s*([^\s`~]*)?.*$")
HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*$")
INLINE_RE = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")

POSIX_LANGUAGES = {"bash", "sh", "zsh", "posix", "shellscript"}
POWERSHELL_LANGUAGES = {"powershell", "pwsh", "ps1"}
CMD_LANGUAGES = {"cmd", "bat", "batch", "dos", "batchfile"}
GENERIC_LANGUAGES = {"", "shell", "console", "terminal", "text", "plaintext"}

COMMAND_STARTERS = {
    ".",
    "./configure",
    "activate",
    "apt",
    "brew",
    "cd",
    "chmod",
    "chown",
    "copy",
    "curl",
    "del",
    "docker",
    "dotnet",
    "echo",
    "export",
    "git",
    "go",
    "gradle",
    "java",
    "make",
    "mkdir",
    "mktemp",
    "npm",
    "npx",
    "pip",
    "pipx",
    "pnpm",
    "py",
    "python",
    "python3",
    "Remove-Item",
    "Get-ChildItem",
    "Set-Location",
    "Expand-Archive",
    "rmdir",
    "rm",
    "set",
    "source",
    "sudo",
    "tar",
    "unzip",
    "uv",
    "uvx",
    "where",
    "which",
    "yarn",
}
COMMAND_STARTERS_CASEFOLD = {item.casefold() for item in COMMAND_STARTERS}


def language_to_dialect(language: str) -> str:
    normalized = language.strip().lower()
    if normalized in POSIX_LANGUAGES:
        return "posix"
    if normalized in POWERSHELL_LANGUAGES:
        return "powershell"
    if normalized in CMD_LANGUAGES:
        return "cmd"
    if normalized in GENERIC_LANGUAGES:
        return "generic"
    return "other"


def parse_markdown(
    path: Path, relative_path: str, text: str
) -> tuple[list[CodeBlock], list[CommandSnippet]]:
    lines = text.splitlines()
    blocks: list[CodeBlock] = []
    snippets: list[CommandSnippet] = []
    heading_stack: list[tuple[int, str]] = []

    open_marker: str | None = None
    open_language = ""
    open_line = 0
    open_heading: str | None = None
    content: list[str] = []

    for index, line in enumerate(lines, start=1):
        if open_marker is None:
            heading_match = HEADING_RE.match(line)
            if heading_match:
                level = len(heading_match.group(1))
                title = heading_match.group(2).strip().rstrip("#").strip()
                heading_stack = [item for item in heading_stack if item[0] < level]
                heading_stack.append((level, title))

            fence_match = FENCE_RE.match(line)
            if fence_match:
                open_marker = fence_match.group(1)
                open_language = (fence_match.group(2) or "").strip()
                open_line = index
                open_heading = " / ".join(item[1] for item in heading_stack) or None
                content = []
                continue

            snippets.extend(
                _inline_snippets(
                    path=path,
                    relative_path=relative_path,
                    line_number=index,
                    line=line,
                    heading=" / ".join(item[1] for item in heading_stack) or None,
                )
            )
            continue

        if _is_closing_fence(line, open_marker):
            dialect = language_to_dialect(open_language)
            block = CodeBlock(
                path=path,
                relative_path=relative_path,
                language=open_language,
                dialect=dialect,
                start_line=open_line,
                end_line=index,
                content_start_line=open_line + 1,
                lines=tuple(content),
                heading=open_heading,
                closed=True,
            )
            blocks.append(block)
            snippets.extend(_block_snippets(block))
            open_marker = None
            open_language = ""
            open_line = 0
            open_heading = None
            content = []
        else:
            content.append(line)

    if open_marker is not None:
        dialect = language_to_dialect(open_language)
        block = CodeBlock(
            path=path,
            relative_path=relative_path,
            language=open_language,
            dialect=dialect,
            start_line=open_line,
            end_line=len(lines),
            content_start_line=open_line + 1,
            lines=tuple(content),
            heading=open_heading,
            closed=False,
        )
        blocks.append(block)
        snippets.extend(_block_snippets(block))

    return blocks, snippets


def _is_closing_fence(line: str, marker: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped[0] != marker[0]:
        return False
    return len(stripped) >= len(marker) and set(stripped) == {marker[0]}


def _block_snippets(block: CodeBlock) -> list[CommandSnippet]:
    if block.dialect == "other":
        return []
    snippets: list[CommandSnippet] = []
    posix_heredoc_end: str | None = None
    powershell_here_string_end: str | None = None
    for offset, raw_line in enumerate(block.lines):
        line_number = block.content_start_line + offset
        if posix_heredoc_end is not None:
            if raw_line.strip() == posix_heredoc_end:
                posix_heredoc_end = None
            continue
        if powershell_here_string_end is not None:
            if raw_line.strip() == powershell_here_string_end:
                powershell_here_string_end = None
            continue

        normalized, column = _normalize_command_line(raw_line, block.dialect)
        if not normalized:
            continue
        if block.dialect == "generic" and not _looks_like_command(normalized):
            continue
        snippets.append(
            CommandSnippet(
                path=block.path,
                relative_path=block.relative_path,
                line=line_number,
                column=column,
                text=normalized,
                dialect=block.dialect,
                source_kind="fence",
                heading=block.heading,
            )
        )
        heredoc = re.search(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1", normalized)
        if heredoc:
            posix_heredoc_end = heredoc.group(2)
        here_string = re.search(r"(?:^|[=(:;,|])\s*@([\"'])\s*$", normalized)
        if here_string:
            powershell_here_string_end = here_string.group(1) + "@"
    return snippets


def _inline_snippets(
    *, path: Path, relative_path: str, line_number: int, line: str, heading: str | None
) -> list[CommandSnippet]:
    snippets: list[CommandSnippet] = []
    for match in INLINE_RE.finditer(line):
        value = match.group(1).strip()
        if not _looks_like_command(value):
            continue
        snippets.append(
            CommandSnippet(
                path=path,
                relative_path=relative_path,
                line=line_number,
                column=match.start(1) + 1,
                text=value,
                dialect="generic",
                source_kind="inline",
                heading=heading,
            )
        )
    return snippets


def _normalize_command_line(line: str, dialect: str) -> tuple[str, int]:
    if not line.strip():
        return "", 1
    leading = len(line) - len(line.lstrip())
    value = line.lstrip()
    if value.startswith("#") or value.startswith("//"):
        return "", leading + 1

    prompt_patterns = [
        re.compile(r"^\$\s+"),
        re.compile(r"^PS(?:\s+[^>]+)?>\s*", re.IGNORECASE),
        re.compile(r"^[A-Za-z]:\\[^>]*>\s*"),
    ]
    if dialect in {"generic", "posix"}:
        prompt_patterns.append(re.compile(r"^#\s+"))
    for pattern in prompt_patterns:
        match = pattern.match(value)
        if match:
            leading += match.end()
            value = value[match.end() :]
            break

    return value.rstrip(), leading + 1


def _looks_like_command(value: str) -> bool:
    stripped = value.strip()
    if not stripped or stripped.startswith(("http://", "https://")):
        return False
    first = stripped.split(maxsplit=1)[0].rstrip(";")
    if first in COMMAND_STARTERS or first.casefold() in COMMAND_STARTERS_CASEFOLD:
        return True
    if re.match(r"^(?:\.{1,2}[\\/]|[A-Za-z]:\\)[^\s]+\.(?:bat|cmd|ps1|sh|bash|exe)\b", first, re.IGNORECASE):
        return True
    markers = (
        "rm -rf",
        "source ",
        "$env:",
        "&&",
        "||",
        ".venv/bin/",
        ".venv\\Scripts\\",
        "2>/dev/null",
        ">NUL",
    )
    return any(marker.lower() in stripped.lower() for marker in markers)
