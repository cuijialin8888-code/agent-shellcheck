from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .models import CommandSnippet, Finding, Rule, Severity


POWERSHELL_ENVIRONMENT = (
    "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/"
    "about/about_environment_variables"
)
POWERSHELL_PARSING = (
    "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/"
    "about/about_parsing"
)
CMD_REFERENCE = "https://learn.microsoft.com/windows-server/administration/windows-commands/cmd"
PYTHON_VENV = "https://docs.python.org/3/library/venv.html"
WSL_FILESYSTEMS = "https://learn.microsoft.com/windows/wsl/filesystems"
BASH_MANUAL = "https://www.gnu.org/software/bash/manual/bash.html"


RULES: tuple[Rule, ...] = (
    Rule(
        "ASC000",
        "Unclosed Markdown fence",
        Severity.ERROR,
        "A command fence reaches end of file without a matching closing fence.",
        "Close the Markdown fence with the same marker and at least the same length.",
        ("markdown",),
    ),
    Rule(
        "ASC001",
        "POSIX environment syntax",
        Severity.ERROR,
        "A POSIX environment assignment is used outside a POSIX shell.",
        "Use the environment-variable syntax for the declared shell, or label this block as Bash.",
        ("posix",),
        (BASH_MANUAL, POWERSHELL_ENVIRONMENT, CMD_REFERENCE),
    ),
    Rule(
        "ASC002",
        "PowerShell environment syntax",
        Severity.ERROR,
        "PowerShell $env:NAME syntax is used outside PowerShell.",
        "Use the environment-variable syntax for the declared shell, or label this block as PowerShell.",
        ("powershell",),
        (POWERSHELL_ENVIRONMENT,),
    ),
    Rule(
        "ASC003",
        "cmd.exe environment syntax",
        Severity.ERROR,
        "cmd.exe environment syntax is used outside cmd.exe.",
        "Use the environment-variable syntax for the declared shell, or label this block as cmd.",
        ("cmd",),
        (CMD_REFERENCE,),
    ),
    Rule(
        "ASC004",
        "POSIX line continuation",
        Severity.ERROR,
        "A POSIX trailing backslash is used under another shell.",
        "Use the continuation syntax for the declared shell, or keep the command on one line.",
        ("posix",),
        (BASH_MANUAL, POWERSHELL_PARSING),
    ),
    Rule(
        "ASC005",
        "PowerShell line continuation",
        Severity.ERROR,
        "A PowerShell trailing backtick is used under another shell.",
        "Use the continuation syntax for the declared shell, or keep the command on one line.",
        ("powershell",),
        (POWERSHELL_PARSING,),
    ),
    Rule(
        "ASC006",
        "cmd.exe line continuation",
        Severity.ERROR,
        "A cmd.exe trailing caret is used under another shell.",
        "Use the continuation syntax for the declared shell, or keep the command on one line.",
        ("cmd",),
        (CMD_REFERENCE,),
    ),
    Rule(
        "ASC007",
        "POSIX heredoc",
        Severity.ERROR,
        "A POSIX heredoc is used outside a POSIX shell.",
        "Use the multiline-input syntax for the declared shell, or invoke Bash explicitly.",
        ("posix",),
        (BASH_MANUAL,),
    ),
    Rule(
        "ASC008",
        "PowerShell here-string",
        Severity.ERROR,
        "A PowerShell here-string is used outside PowerShell.",
        "Use the multiline-string syntax for the declared shell, or invoke PowerShell explicitly.",
        ("powershell",),
        (POWERSHELL_PARSING,),
    ),
    Rule(
        "ASC009",
        "POSIX null device",
        Severity.ERROR,
        "Output is redirected to /dev/null outside a POSIX shell.",
        "Use the null sink for the declared shell, or label this block as Bash/WSL.",
        ("posix",),
        (BASH_MANUAL,),
    ),
    Rule(
        "ASC010",
        "PowerShell null redirection",
        Severity.ERROR,
        "Output is redirected to PowerShell $null outside PowerShell.",
        "Use the null sink for the declared shell, or label this block as PowerShell.",
        ("powershell",),
        (POWERSHELL_ENVIRONMENT,),
    ),
    Rule(
        "ASC011",
        "POSIX command signature",
        Severity.WARNING,
        "A high-confidence POSIX-only command signature is used outside POSIX.",
        "Provide a command for the declared shell or label the platform-specific alternative.",
        ("posix",),
        (BASH_MANUAL,),
    ),
    Rule(
        "ASC012",
        "PowerShell cmdlet",
        Severity.ERROR,
        "A PowerShell-only cmdlet is used outside PowerShell.",
        "Provide a command for the declared shell or label this block as PowerShell.",
        ("powershell",),
        (POWERSHELL_PARSING,),
    ),
    Rule(
        "ASC013",
        "cmd.exe built-in",
        Severity.ERROR,
        "A cmd.exe-only command signature is used outside cmd.exe.",
        "Provide a command for the declared shell or label this block as cmd.",
        ("cmd",),
        (CMD_REFERENCE,),
    ),
    Rule(
        "ASC014",
        "Windows drive path in Bash",
        Severity.WARNING,
        "A Windows drive-letter path is passed to a POSIX file operation.",
        "Use a POSIX/WSL path, convert it with wslpath, or invoke a Windows executable explicitly.",
        ("posix", "windows"),
        (WSL_FILESYSTEMS,),
    ),
    Rule(
        "ASC015",
        "Windows relative path in Bash",
        Severity.ERROR,
        "A Windows-style relative executable path is used in Bash.",
        "Use forward slashes and invoke PowerShell explicitly for .ps1 scripts when needed.",
        ("posix", "windows"),
        (WSL_FILESYSTEMS,),
    ),
    Rule(
        "ASC016",
        "Virtual-environment activation mismatch",
        Severity.ERROR,
        "A Python virtual-environment activation command conflicts with the declared shell.",
        "Use the activation script documented for this shell, or run the environment's Python directly.",
        ("posix", "powershell", "cmd"),
        (PYTHON_VENV,),
    ),
    Rule(
        "ASC017",
        "Command substitution in cmd.exe",
        Severity.ERROR,
        "POSIX/PowerShell $() command substitution is used in cmd.exe.",
        "Split the operation into cmd.exe-compatible steps or invoke the intended shell explicitly.",
        ("posix", "powershell", "cmd"),
        (CMD_REFERENCE,),
    ),
    Rule(
        "ASC018",
        "POSIX source builtin",
        Severity.ERROR,
        "The POSIX source builtin is used outside a POSIX shell.",
        "Use the declared shell's invocation mechanism, or invoke Bash explicitly.",
        ("posix",),
        (BASH_MANUAL,),
    ),
    Rule(
        "ASC019",
        "Direct batch execution in WSL",
        Severity.ERROR,
        "A .bat or .cmd file is invoked directly from WSL Bash.",
        "Invoke the batch file through cmd.exe /d /c and validate its quoting and path.",
        ("posix", "cmd", "wsl"),
        (WSL_FILESYSTEMS,),
    ),
)

RULE_BY_ID = {rule.rule_id: rule for rule in RULES}

TARGET_ALIASES = {
    "posix": "bash-linux",
    "windows": "powershell-windows",
}
TARGETS = (
    "auto",
    "portable",
    "bash-linux",
    "bash-wsl",
    "powershell-windows",
    "cmd-windows",
    "posix",
    "windows",
)

NEGATIVE_HEADING_MARKERS = (
    "anti-pattern",
    "antipattern",
    "bad example",
    "do not",
    "don't",
    "incorrect",
    "not to do",
    "wrong example",
    "不应",
    "不要",
    "反例",
    "禁止",
    "错误示例",
)

POWERSHELL_CMDLETS = (
    "Add-Content",
    "Copy-Item",
    "Expand-Archive",
    "Get-ChildItem",
    "Get-Command",
    "Get-Content",
    "Invoke-RestMethod",
    "Invoke-WebRequest",
    "Join-Path",
    "Move-Item",
    "New-Item",
    "Remove-Item",
    "Resolve-Path",
    "Set-Content",
    "Set-Location",
    "Test-Path",
    "Where-Object",
    "Write-Host",
    "Write-Output",
)


@dataclass(frozen=True)
class TargetContext:
    name: str
    shell: str
    host: str
    confidence: str


def canonical_target(value: str) -> str:
    return TARGET_ALIASES.get(value, value)


def evaluate_snippet(snippet: CommandSnippet, requested_target: str) -> list[Finding]:
    if _negative_heading(snippet.heading):
        return []

    text = _strip_trailing_comment(snippet.text)
    if not text or _is_shell_wrapper(text):
        return []

    context = _resolve_context(snippet, requested_target)
    candidates: list[tuple[str, str, str, int | None]] = []

    venv_kind = _venv_activation_kind(text)
    if venv_kind and not _shell_accepts(context, venv_kind):
        candidates.append(
            (
                "ASC016",
                f"{_shell_label(venv_kind)} virtual-environment activation is incompatible with {_context_label(context)}",
                _evidence(text, _venv_pattern(venv_kind)),
                None,
            )
        )

    if venv_kind is None:
        if _matches_posix_environment(text) and not _shell_accepts(context, "posix"):
            candidates.append(
                (
                    "ASC001",
                    f"POSIX environment assignment is incompatible with {_context_label(context)}",
                    _evidence(text, re.compile(r"\bexport\b|^[A-Za-z_]\w*=")),
                    None,
                )
            )

        if _starts_source(text) and not _shell_accepts(context, "posix"):
            candidates.append(
                (
                    "ASC018",
                    f"POSIX source builtin is incompatible with {_context_label(context)}",
                    _evidence(text, re.compile(r"\bsource\b")),
                    None,
                )
            )

    if _matches_powershell_environment(text) and not _shell_accepts(context, "powershell"):
        candidates.append(
            (
                "ASC002",
                f"PowerShell environment syntax is incompatible with {_context_label(context)}",
                _evidence(text, re.compile(r"\$\{?env:[A-Za-z_]\w*\}?", re.IGNORECASE)),
                None,
            )
        )

    if _matches_cmd_environment(text) and not _shell_accepts(context, "cmd"):
        candidates.append(
            (
                "ASC003",
                f"cmd.exe environment syntax is incompatible with {_context_label(context)}",
                _evidence(
                    text,
                    re.compile(r"%[A-Za-z_][A-Za-z0-9_()]*%|^\s*@?set\s+\"?[A-Za-z_]\w*=", re.IGNORECASE),
                ),
                None,
            )
        )

    if _posix_continuation(text) and not _shell_accepts(context, "posix"):
        candidates.append(("ASC004", f"POSIX line continuation is incompatible with {_context_label(context)}", "\\", None))

    if _powershell_continuation(text) and not _shell_accepts(context, "powershell"):
        candidates.append(("ASC005", f"PowerShell line continuation is incompatible with {_context_label(context)}", "`", None))

    if _cmd_continuation(text) and not _shell_accepts(context, "cmd"):
        candidates.append(("ASC006", f"cmd.exe line continuation is incompatible with {_context_label(context)}", "^", None))

    if _matches_posix_heredoc(text) and not _shell_accepts(context, "posix"):
        candidates.append(
            (
                "ASC007",
                f"POSIX heredoc is incompatible with {_context_label(context)}",
                _evidence(text, re.compile(r"<<<|<<-?\s*(['\"]?)[A-Za-z_]\w*\1")),
                None,
            )
        )

    if _matches_powershell_here_string(text) and not _shell_accepts(context, "powershell"):
        candidates.append(
            (
                "ASC008",
                f"PowerShell here-string is incompatible with {_context_label(context)}",
                _evidence(text, re.compile(r"@[\"']")),
                None,
            )
        )

    if re.search(r"(?:^|\s)\d*>+\s*/dev/null\b", text, re.IGNORECASE) and not _shell_accepts(context, "posix"):
        candidates.append(("ASC009", f"/dev/null redirection is incompatible with {_context_label(context)}", "/dev/null", None))

    if re.search(r"(?:^|\s)\d*>+\s*\$null\b", text, re.IGNORECASE) and not _shell_accepts(context, "powershell"):
        candidates.append(("ASC010", f"PowerShell $null redirection is incompatible with {_context_label(context)}", "$null", None))

    posix_signature = _posix_command_signature(text)
    if posix_signature and not _shell_accepts(context, "posix"):
        candidates.append(
            (
                "ASC011",
                f"POSIX command signature is not portable to {_context_label(context)}",
                posix_signature,
                Severity.WARNING.value,
            )
        )

    cmdlet = _powershell_cmdlet(text)
    if cmdlet and not _shell_accepts(context, "powershell"):
        candidates.append(
            (
                "ASC012",
                f"PowerShell cmdlet is incompatible with {_context_label(context)}",
                cmdlet,
                None,
            )
        )

    if not _matches_cmd_environment(text):
        cmd_builtin = _cmd_builtin(text)
        if cmd_builtin and not _shell_accepts(context, "cmd"):
            candidates.append(
                (
                    "ASC013",
                    f"cmd.exe built-in syntax is incompatible with {_context_label(context)}",
                    cmd_builtin,
                    None,
                )
            )

    if context.shell == "posix" and venv_kind is None:
        drive_path = _windows_drive_path_for_posix_operation(text)
        if drive_path:
            candidates.append(
                (
                    "ASC014",
                    "Windows drive path is passed directly to a POSIX file operation",
                    drive_path,
                    Severity.WARNING.value,
                )
            )
        relative_path = _windows_relative_executable(text)
        if relative_path:
            candidates.append(
                (
                    "ASC015",
                    "Windows-style relative executable path is incompatible with Bash",
                    relative_path,
                    None,
                )
            )

    if context.shell == "cmd" and re.search(r"\$\([^\r\n)]+\)", text):
        candidates.append(
            (
                "ASC017",
                "$(...) command substitution is not interpreted by cmd.exe",
                _evidence(text, re.compile(r"\$\([^\r\n)]+\)")),
                None,
            )
        )

    if context.name == "bash-wsl":
        batch = _direct_batch_invocation(text)
        if batch:
            candidates.append(
                (
                    "ASC019",
                    "Batch files require an explicit Windows command host when called from WSL",
                    batch,
                    None,
                )
            )

    findings: list[Finding] = []
    seen_rules: set[str] = set()
    for rule_id, message, evidence, severity_value in candidates:
        if rule_id in seen_rules:
            continue
        seen_rules.add(rule_id)
        rule = RULE_BY_ID[rule_id]
        severity = _severity_for(context, rule)
        if severity_value is not None:
            severity = Severity(severity_value)
            if context.confidence == "unknown":
                severity = Severity.INFO
        column = snippet.column + max(text.find(evidence), 0)
        findings.append(
            Finding(
                rule=rule,
                severity=severity,
                relative_path=snippet.relative_path,
                line=snippet.line,
                column=column,
                message=message,
                evidence=evidence,
                properties={
                    "sourceKind": snippet.source_kind,
                    "declaredDialect": snippet.dialect,
                    "resolvedTarget": context.name,
                },
            )
        )
    return findings


def iter_rules(rule_ids: Iterable[str] | None = None) -> list[Rule]:
    if rule_ids is None:
        return list(RULES)
    selected = set(rule_ids)
    return [rule for rule in RULES if rule.rule_id in selected]


def _resolve_context(snippet: CommandSnippet, requested: str) -> TargetContext:
    requested = canonical_target(requested)
    heading_target = _target_from_heading(snippet.heading)

    if snippet.dialect == "powershell":
        return TargetContext("powershell-windows", "powershell", "windows", "declared")
    if snippet.dialect == "cmd":
        return TargetContext("cmd-windows", "cmd", "windows", "declared")
    if snippet.dialect == "posix":
        if requested == "bash-wsl" or heading_target == "bash-wsl":
            return TargetContext("bash-wsl", "posix", "wsl", "declared")
        return TargetContext("bash-linux", "posix", "linux", "declared")

    if heading_target:
        return _context_for_target(heading_target, "heading")
    if requested not in {"auto", "portable"}:
        return _context_for_target(requested, "requested")
    if requested == "portable":
        return TargetContext("portable", "portable", "portable", "requested")
    return TargetContext("auto", "unknown", "unknown", "unknown")


def _context_for_target(target: str, confidence: str) -> TargetContext:
    mapping = {
        "bash-linux": ("posix", "linux"),
        "bash-wsl": ("posix", "wsl"),
        "powershell-windows": ("powershell", "windows"),
        "cmd-windows": ("cmd", "windows"),
    }
    shell, host = mapping[target]
    return TargetContext(target, shell, host, confidence)


def _target_from_heading(heading: str | None) -> str | None:
    if not heading:
        return None
    value = heading.casefold()
    if "wsl" in value or "windows subsystem for linux" in value:
        return "bash-wsl"
    if "powershell" in value or "pwsh" in value:
        return "powershell-windows"
    if "command prompt" in value or re.search(r"\bcmd(?:\.exe)?\b", value):
        return "cmd-windows"
    if any(marker in value for marker in ("bash", "linux", "macos", "mac os", "posix")):
        return "bash-linux"
    return None


def _negative_heading(heading: str | None) -> bool:
    if not heading:
        return False
    normalized = heading.casefold()
    return any(marker in normalized for marker in NEGATIVE_HEADING_MARKERS)


def _shell_accepts(context: TargetContext, native_shell: str) -> bool:
    return context.shell == native_shell


def _severity_for(context: TargetContext, rule: Rule) -> Severity:
    if context.confidence == "unknown":
        return Severity.INFO
    return rule.default_severity


def _shell_label(shell: str) -> str:
    return {"posix": "Bash/POSIX", "powershell": "PowerShell", "cmd": "cmd.exe"}[shell]


def _context_label(context: TargetContext) -> str:
    labels = {
        "auto": "an unlabeled portable context",
        "portable": "a portable context",
        "bash-linux": "Bash on Linux",
        "bash-wsl": "Bash under WSL",
        "powershell-windows": "PowerShell on Windows",
        "cmd-windows": "cmd.exe on Windows",
    }
    return labels[context.name]


def _strip_trailing_comment(text: str) -> str:
    single = False
    double = False
    escaped = False
    for index, character in enumerate(text):
        if escaped:
            escaped = False
            continue
        if character == "\\" and not single:
            escaped = True
            continue
        if character == "'" and not double:
            single = not single
            continue
        if character == '"' and not single:
            double = not double
            continue
        if character == "#" and not single and not double:
            if index == 0 or text[index - 1].isspace():
                return text[:index].rstrip()
    return text.rstrip()


def _is_shell_wrapper(text: str) -> bool:
    return bool(
        re.match(
            r"^\s*(?:bash|sh|zsh)\b.*(?:-[A-Za-z]*c|--command)\b|"
            r"^\s*(?:pwsh|powershell(?:\.exe)?)\b.*(?:-c|-command)\b|"
            r"^\s*cmd(?:\.exe)?\b.*(?:/c|/k)\b",
            text,
            re.IGNORECASE,
        )
    )


def _matches_posix_environment(text: str) -> bool:
    return bool(
        re.match(r"^\s*(?:export\s+[A-Za-z_]\w*(?:=|\s|$)|[A-Za-z_]\w*=\S+(?:\s+\S+|$))", text)
    )


def _matches_powershell_environment(text: str) -> bool:
    return bool(re.search(r"\$\{?env:[A-Za-z_]\w*\}?", _remove_single_quoted(text), re.IGNORECASE))


def _matches_cmd_environment(text: str) -> bool:
    if re.match(r"^\s*@?set\s+\"?[A-Za-z_]\w*=", text, re.IGNORECASE):
        return True
    return bool(re.search(r"%[A-Za-z_][A-Za-z0-9_()]*%", _remove_quoted(text)))


def _starts_source(text: str) -> bool:
    return bool(re.match(r"^\s*source(?:\s|$)", text))


def _posix_continuation(text: str) -> bool:
    stripped = text.rstrip()
    if re.search(r"(?:^|\s)[A-Za-z]:\\$", stripped):
        return False
    trailing = len(stripped) - len(stripped.rstrip("\\"))
    return trailing % 2 == 1


def _powershell_continuation(text: str) -> bool:
    stripped = text.rstrip()
    return stripped.endswith("`") and not stripped.endswith("``")


def _cmd_continuation(text: str) -> bool:
    stripped = text.rstrip()
    trailing = len(stripped) - len(stripped.rstrip("^"))
    return trailing % 2 == 1


def _matches_posix_heredoc(text: str) -> bool:
    return bool(re.search(r"(?:^|\s)(?:\d*)<<<|(?:^|\s)(?:\d*)<<-?\s*['\"]?[A-Za-z_]\w*", text))


def _matches_powershell_here_string(text: str) -> bool:
    return bool(re.search(r"(?:^|[=(:;,|])\s*@[\"']\s*$", text))


def _posix_command_signature(text: str) -> str | None:
    patterns = (
        re.compile(r"^\s*(?:sudo)(?:\s|$)", re.IGNORECASE),
        re.compile(r"^\s*rm\s+-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*(?:\s|$)", re.IGNORECASE),
        re.compile(r"^\s*rm\s+-[A-Za-z]*f[A-Za-z]*r[A-Za-z]*(?:\s|$)", re.IGNORECASE),
        re.compile(r"^\s*chmod\s+\+x(?:\s|$)", re.IGNORECASE),
        re.compile(r"^\s*test\s+-[fde](?:\s|$)", re.IGNORECASE),
    )
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            return match.group(0).strip()
    return None


def _powershell_cmdlet(text: str) -> str | None:
    match = re.match(r"^\s*&?\s*([A-Za-z]+-[A-Za-z][A-Za-z0-9]*)\b", text)
    if not match:
        return None
    candidate = match.group(1)
    known = {value.casefold(): value for value in POWERSHELL_CMDLETS}
    return candidate if candidate.casefold() in known else None


def _cmd_builtin(text: str) -> str | None:
    patterns = (
        re.compile(r"^\s*if\s+errorlevel\b", re.IGNORECASE),
        re.compile(r"^\s*for\s+/f\b", re.IGNORECASE),
        re.compile(r"^\s*dir\s+/[A-Za-z]*b[A-Za-z]*(?:\s|$)", re.IGNORECASE),
        re.compile(r"^\s*del\s+/[A-Za-z]*q[A-Za-z]*(?:\s|$)", re.IGNORECASE),
        re.compile(r"^\s*rmdir\s+/s\s+/q(?:\s|$)", re.IGNORECASE),
    )
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            return match.group(0).strip()
    return None


def _windows_drive_path_for_posix_operation(text: str) -> str | None:
    if re.search(r"\b(?:[A-Za-z0-9_.-]+\.exe|wslpath)\b", text, re.IGNORECASE):
        return None
    if not re.match(r"^\s*(?:cd|ls|rm|cp|mv|cat|chmod|chown|test|source|\.)\b", text):
        return None
    match = re.search(r"(?<![A-Za-z0-9_])[A-Za-z]:\\[^\s'\"]*", text)
    return match.group(0) if match else None


def _windows_relative_executable(text: str) -> str | None:
    if re.match(r"^\s*(?:cmd(?:\.exe)?|pwsh|powershell(?:\.exe)?)\b", text, re.IGNORECASE):
        return None
    match = re.match(r"^\s*(\.\\[^\s'\"]+)", text)
    return match.group(1) if match else None


def _venv_activation_kind(text: str) -> str | None:
    if re.match(r"^\s*(?:source|\.)\s+[^\s]*\.venv/bin/activate(?:\s|$)", text, re.IGNORECASE):
        return "posix"
    if re.match(r"^\s*(?:\.\s+)?(?:\.\\)?[^\s]*\.venv\\Scripts\\Activate\.ps1(?:\s|$)", text, re.IGNORECASE):
        return "powershell"
    if re.match(r"^\s*(?:call\s+)?(?:\.\\)?[^\s]*\.venv\\Scripts\\activate\.bat(?:\s|$)", text, re.IGNORECASE):
        return "cmd"
    return None


def _venv_pattern(kind: str) -> re.Pattern[str]:
    patterns = {
        "posix": re.compile(r"(?:source|\.)\s+[^\s]*\.venv/bin/activate", re.IGNORECASE),
        "powershell": re.compile(r"[^\s]*\.venv\\Scripts\\Activate\.ps1", re.IGNORECASE),
        "cmd": re.compile(r"[^\s]*\.venv\\Scripts\\activate\.bat", re.IGNORECASE),
    }
    return patterns[kind]


def _direct_batch_invocation(text: str) -> str | None:
    if re.match(r"^\s*cmd(?:\.exe)?\b", text, re.IGNORECASE):
        return None
    match = re.match(r"^\s*(?:(?:\./|\.\\)?[^\s'\"]+\.(?:bat|cmd))\b", text, re.IGNORECASE)
    return match.group(0).strip() if match else None


def _remove_single_quoted(text: str) -> str:
    output: list[str] = []
    inside = False
    for character in text:
        if character == "'":
            inside = not inside
            output.append(" ")
        elif inside:
            output.append(" ")
        else:
            output.append(character)
    return "".join(output)


def _remove_quoted(text: str) -> str:
    output: list[str] = []
    quote: str | None = None
    escaped = False
    for character in text:
        if escaped:
            output.append(" ")
            escaped = False
            continue
        if character == "\\" and quote == '"':
            output.append(" ")
            escaped = True
            continue
        if quote is None and character in {"'", '"'}:
            quote = character
            output.append(" ")
        elif quote == character:
            quote = None
            output.append(" ")
        elif quote is not None:
            output.append(" ")
        else:
            output.append(character)
    return "".join(output)


def _evidence(text: str, pattern: re.Pattern[str]) -> str:
    match = pattern.search(text)
    return match.group(0).strip() if match else text.strip()
