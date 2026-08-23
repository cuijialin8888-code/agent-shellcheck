# Rule reference

Rule IDs are stable API. A rule may become more precise over time, but its ID
will not be silently reused for a different portability problem. Severity and
failure policy are separate: `--min-severity` controls displayed findings, and
`--fail-on` controls the process status (`error` by default).

## Catalog

| ID | Name | What it detects |
|---|---|---|
| `ASC000` | `UNCLOSED_FENCE` | A Markdown command block reaches end of file without a matching closing fence. |
| `ASC001` | `POSIX_ENV_SYNTAX` | POSIX environment assignment or expansion in an incompatible or portable context. |
| `ASC002` | `POWERSHELL_ENV_SYNTAX` | PowerShell `$env:NAME` syntax outside a compatible PowerShell context. |
| `ASC003` | `CMD_ENV_SYNTAX` | cmd.exe `%NAME%` or `set NAME=value` syntax outside a compatible cmd context. |
| `ASC004` | `POSIX_LINE_CONTINUATION` | A trailing POSIX backslash used where that continuation syntax is not valid. |
| `ASC005` | `POWERSHELL_LINE_CONTINUATION` | A PowerShell backtick continuation under another shell target. |
| `ASC006` | `CMD_LINE_CONTINUATION` | A cmd.exe caret continuation under another shell target. |
| `ASC007` | `POSIX_HEREDOC` | A POSIX `<<MARKER` heredoc in a non-POSIX command block. |
| `ASC008` | `POWERSHELL_HERESTRING` | A PowerShell `@"..."@` or `@'...'@` here-string in a non-PowerShell block. |
| `ASC009` | `POSIX_NULL_DEVICE` | `/dev/null` used outside a POSIX-compatible target. |
| `ASC010` | `POWERSHELL_NULL_REDIRECT` | PowerShell redirection to `$null` used outside PowerShell. |
| `ASC011` | `POSIX_COMMAND_SIGNATURE` | A high-confidence POSIX-only command or option signature in an incompatible or portable context. |
| `ASC012` | `POWERSHELL_CMDLET` | A PowerShell-only cmdlet, such as `Get-ChildItem` or `Remove-Item`, outside PowerShell. |
| `ASC013` | `CMD_BUILTIN` | A cmd.exe-only built-in signature outside cmd.exe. |
| `ASC014` | `WINDOWS_DRIVE_PATH_IN_BASH` | A drive-letter path such as `C:\\work` inside a Bash block. |
| `ASC015` | `WINDOWS_RELATIVE_PATH_IN_BASH` | A Windows relative path such as `.\\scripts\\build.ps1` inside a Bash block. |
| `ASC016` | `VENV_ACTIVATION_MISMATCH` | A Python virtual-environment activation path that conflicts with the declared shell. |
| `ASC017` | `COMMAND_SUBSTITUTION_IN_CMD` | POSIX/PowerShell `$()` command substitution inside a cmd.exe block. |
| `ASC018` | `POSIX_SOURCE_BUILTIN` | The Bash `source` builtin used where it is unavailable or ambiguous. |
| `ASC019` | `WSL_DIRECT_BATCH_EXEC` | A `.bat` or `.cmd` file invoked directly from WSL Bash instead of through a Windows command host. |

## Target model

`agent-shellcheck` separates *what a block says it is* from *where the user
plans to run it*:

| Target | Intended use |
|---|---|
| `auto` | Infer dialect from fence labels and nearby context; evaluate unlabeled command snippets conservatively. |
| `portable` | Surface syntax that binds otherwise generic instructions to one supported shell family. |
| `bash-linux` | Evaluate generic snippets as Bash on Linux. |
| `bash-wsl` | Evaluate generic snippets as Bash under Windows Subsystem for Linux. |
| `powershell-windows` | Evaluate generic snippets as PowerShell on native Windows. |
| `cmd-windows` | Evaluate generic snippets as cmd.exe on native Windows. |

`posix` and `windows` are compatibility aliases for the corresponding canonical
targets. New integrations should prefer the full canonical names because they
make the actual shell/host pair visible.

Explicitly labelled platform examples are useful documentation. A Bash block is
not automatically a portability bug in a cross-platform document; the scanner
checks whether the block's contents agree with its declared and requested
context.

## Examples

### Environment syntax conflicts with its fence

````markdown
```powershell
export TOOL_HOME="$HOME/.tool"
source .venv/bin/activate
```
````

`ASC001` identifies the POSIX environment assignment and `ASC018` identifies
the POSIX `source` builtin. Changing the fence to `bash` is correct only if Bash
was truly intended; otherwise provide PowerShell commands.

### Labelled virtual-environment alternatives

````markdown
**Bash (Linux or WSL)**

```bash
python -m venv .venv
. .venv/bin/activate
```

**PowerShell (Windows)**

```powershell
py -m venv .venv
. .venv\Scripts\Activate.ps1
```
````

`ASC016` focuses on mismatched activation paths—for example,
`.venv\Scripts\Activate.ps1` fenced as Bash or `.venv/bin/activate` fenced as
PowerShell—not on correctly labelled alternatives.

### Continuations are not interchangeable

````markdown
```cmd
python -m tool --input data \
  --format json
```
````

The backslash is a POSIX continuation, while cmd.exe uses a caret. `ASC004`
reports the conflict. PowerShell uses a backtick, covered by `ASC005`; a caret
in the wrong block is covered by `ASC006`.

### WSL does not execute batch files like cmd.exe

````markdown
```bash
./scripts/setup.cmd --quiet
```
````

Under a `bash-wsl` target, `ASC019` points out the direct batch invocation. Make
the Windows command host explicit, for example `cmd.exe /c scripts\\setup.cmd
--quiet`, and validate quoting for the real path and arguments.

## Policy controls

The rule set and CI policy are intentionally independent:

```console
# Show warning and error findings; fail only on errors (the default threshold).
agent-shellcheck . --min-severity warning --fail-on error

# Temporarily ignore one stable rule while preserving all other diagnostics.
agent-shellcheck . --ignore ASC012

# Bound monorepo discovery.
agent-shellcheck . --exclude "vendor/**" --max-files 500
```

Prefer a narrow rule ignore to discarding an entire file. Record the reason in
version control and revisit it when platform support changes.

## Deliberate boundaries

- The rules recognize high-signal text patterns; they are not full parsers for
  every shell grammar.
- Common cross-shell aliases are not treated as proof of compatibility by name
  alone; rules prefer distinctive syntax or command signatures.
- A command being portable does not make it safe. Security review remains a
  separate task.
- Dynamic commands assembled by a script may be outside static visibility.
- The scanner reports evidence but does not rewrite the source automatically.

## Primary references

- [PowerShell about environment variables](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [PowerShell about parsing](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_parsing)
- [PowerShell about special characters](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_special_characters)
- [PowerShell about redirection](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_redirection)
- [Python virtual environments](https://docs.python.org/3/library/venv.html)
- [Windows Subsystem for Linux interop](https://learn.microsoft.com/windows/wsl/filesystems#run-windows-tools-from-linux)
- [GNU Bash redirections](https://www.gnu.org/software/bash/manual/html_node/Redirections.html)
- [GNU Bash command substitution](https://www.gnu.org/software/bash/manual/html_node/Command-Substitution.html)
- [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
