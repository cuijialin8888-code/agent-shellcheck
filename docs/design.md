# Design and trust model

## Goal

Agent instruction files increasingly contain executable-looking setup,
validation, and cleanup commands. Those commands are often copied between
Linux, WSL, PowerShell, and cmd.exe without a portability review. This project
makes that failure mode visible before a person or coding agent follows the
instructions.

## Pipeline

```text
bounded discovery
      ↓
Markdown fences and command-like snippets
      ↓
dialect and target classification
      ↓
high-signal rule evaluation
      ↓
stable, sorted findings
      ↓
text / JSON / SARIF / Markdown / HTML
```

The pipeline is intentionally one-way. Discovered command text is never sent to
a shell, interpreter, network service, or model.

## Invariants

1. **Static:** scanning analyzes text; it does not execute or probe commands.
2. **Offline:** runtime analysis does not require a network connection.
3. **Read-only by default:** input files are never rewritten. Only an explicitly
   requested report path may be created or replaced.
4. **Deterministic:** file discovery, policy precedence, and findings use stable ordering.
5. **Bounded:** ignored dependency/build directories, symlinks, and oversized
   files are not recursively explored.
6. **Explainable:** every finding names a stable rule, exact source location,
   evidence, affected shells, and practical help.
7. **Conservative:** add a narrow diagnostic with a non-triggering test before
   considering a broad heuristic.

## Discovery scope

Directory scans recognize common instruction files:

- `AGENTS.md` and `AGENTS.override.md`
- `SKILL.md`
- `CLAUDE.md` and `CLAUDE.local.md`
- `GEMINI.md`
- `.cursorrules` and `.clinerules`
- `*.instructions.md` and `*.mdc`

Explicit Markdown file paths can be scanned even when their names are not in
this list. Dependency, cache, version-control, build, and virtual-environment
directories are skipped. Symbolic links are not followed, and files larger than
1 MiB are skipped during directory discovery.

## Non-goals

`agent-shellcheck` does not aim to:

- parse every shell grammar or infer arbitrary runtime state;
- replace ShellCheck, PSScriptAnalyzer, or shell-specific tests;
- judge the quality or completeness of natural-language agent instructions;
- identify malware, prompt injection, secrets, or every unsafe command;
- execute a command to see whether it works; or
- rewrite instruction files automatically.

These boundaries keep the tool suitable for untrusted repositories and make
findings easier to reproduce.

Repository policy is parsed locally from bounded UTF-8 JSON. Schema references
are metadata for editors; the scanner never resolves them over the network.
Unknown keys fail closed so a misspelled safety bound or ignore rule cannot be
silently accepted. Repository-controlled paths are confined to the policy
directory, including after symlink resolution, so an untrusted checkout cannot
redirect a default scan into parent or absolute locations.
