# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A CI adoption guide covering policy files, native annotations, permissions, and immutable release pinning.

### Fixed

- `--fail-on` now evaluates all non-ignored findings even when `--min-severity`
  hides them from the rendered report.

## [0.2.0] - 2026-09-07

### Added

- Repository-level `.agent-shellcheck.json` policy with bounded discovery,
  strict validation, a published JSON Schema, and `--config`, `--no-config`,
  and `--show-config` controls.
- Native GitHub Actions annotations through `--format github`, including exact
  file, line, column, severity, and stable rule ID.

### Changed

- The composite action now emits native pull-request annotations by default.
- Configuration values follow an explicit CLI > repository > built-in
  precedence contract while preserving zero runtime dependencies.

## [0.1.0] - 2026-08-23

### Added

- Static, offline checks for command portability in common agent instruction
  files.
- Twenty stable diagnostics covering Markdown fences, environment-variable
  syntax, continuation characters, multiline input, null redirection, command
  signatures, platform paths, virtual environments, and WSL batch execution.
- `auto`, `portable`, `bash-linux`, `bash-wsl`, `powershell-windows`, and
  `cmd-windows` targets.
- Text, JSON, SARIF, Markdown, and self-contained HTML reports.
- Deterministic discovery with no command execution and no runtime dependencies.

[Unreleased]: https://github.com/cuijialin8888-code/agent-shellcheck/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/cuijialin8888-code/agent-shellcheck/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/cuijialin8888-code/agent-shellcheck/releases/tag/v0.1.0
