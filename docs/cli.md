# Command-line reference

```text
agent-shellcheck [PATH ...] [OPTIONS]
```

With no path, the scanner uses the current directory. Pass one or more files or
directories to constrain discovery.

## Options

| Option | Meaning |
|---|---|
| `--target TARGET` | Select `auto` (default), `portable`, `bash-linux`, `bash-wsl`, `powershell-windows`, or `cmd-windows`. `posix` and `windows` remain compatibility aliases. |
| `--format FORMAT` | Emit `text` (default), `json`, `sarif`, `markdown`, or `html`. |
| `--output PATH` | Write the report to a file instead of standard output. Source instruction files are never modified. |
| `--min-severity LEVEL` | Show findings at or above `info`, `warning`, or `error`. |
| `--fail-on LEVEL` | Return status `1` when a finding reaches this level. Default: `error`. |
| `--ignore RULE_ID` | Omit a stable rule ID such as `ASC012`. Repeat to ignore more than one rule. |
| `--exclude GLOB` | Exclude matching paths during directory discovery. Repeat for more patterns. |
| `--max-files NUMBER` | Stop bounded discovery from scanning more than this many matching files. |
| `--version` | Print the installed version. |
| `-h`, `--help` | Print built-in help. |

## Common invocations

```console
# Infer each labelled block and examine generic snippets conservatively.
agent-shellcheck .

# Check an explicit document and a skill directory for portable instructions.
agent-shellcheck AGENTS.md skills/ --target portable

# Keep warnings visible in SARIF, but block CI only on errors.
agent-shellcheck . --format sarif --output report.sarif \
  --min-severity warning --fail-on error

# Bound a monorepo scan.
agent-shellcheck . --exclude "vendor/**" --exclude "generated/**" --max-files 500
```

On PowerShell, use its backtick or a single line instead of copying the POSIX
backslash continuation from the example above.

## Output discipline

- Reports go to standard output unless `--output` is present.
- Usage and operational errors go to standard error.
- `json` and `sarif` standard output contains only the serialized document, so
  it can be redirected safely.
- Findings use relative paths where possible and stable sorting by path, line,
  column, and rule.

See [outputs](outputs.md) for the JSON schema overview, SARIF integration, and
exit-status contract.
