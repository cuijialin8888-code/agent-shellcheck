# Output formats and automation contract

The same sorted finding set is available in six formats:

| Format | Best for | Notes |
|---|---|---|
| `text` | Local terminals | Compact `path:line:column` diagnostics and a summary. |
| `json` | Scripts and integrations | Versioned schema with rules, evidence, counts, and scan metadata. |
| `sarif` | GitHub code scanning | SARIF 2.1.0 with physical locations and rule metadata. |
| `markdown` | Job summaries and review comments | Human-readable table plus scan totals. |
| `html` | Sharing an offline report | Self-contained document with no remote assets or scripts. |
| `github` | Pull-request checks | Native workflow annotations with exact file, line, column, severity, and rule ID. |

Choose a format with `--format` and write it with `--output`:

```console
agent-shellcheck . --target portable --format json --output report.json
agent-shellcheck . --target portable --format sarif --output report.sarif
agent-shellcheck . --target portable --format github
```

Without `--output`, the report is written to standard output. Diagnostics and
summary order are deterministic for the same project tree, target, and tool
version.

Policy controls are independent of serialization:

```console
agent-shellcheck . --min-severity warning --fail-on error
```

`--min-severity` filters displayed findings. `--fail-on` sets the lowest
severity that makes a completed scan return status `1`; its default is `error`.
This lets a team record warnings in SARIF without immediately making them a
merge blocker.

## JSON schema overview

The top-level object contains:

```json
{
  "schemaVersion": 1,
  "tool": {"name": "agent-shellcheck", "version": "0.2.0"},
  "root": "/work/project",
  "target": "portable",
  "summary": {
    "filesScanned": 2,
    "blocksScanned": 4,
    "snippetsScanned": 6,
    "skippedFiles": 0,
    "findingCount": 1,
    "error": 1,
    "warning": 0,
    "info": 0
  },
  "findings": []
}
```

Each finding includes `ruleId`, `severity`, `path`, `line`, `column`, `message`,
`evidence`, `help`, `affectedShells`, and an extensible `properties` object.
Consumers should ignore unknown fields and check `schemaVersion` before relying
on field semantics.

## Exit status

| Code | Meaning |
|---:|---|
| `0` | Scan completed and no policy-triggering findings were emitted. |
| `1` | Scan completed and findings were emitted. |
| `2` | The invocation or scan could not be completed, for example invalid arguments or an unreadable explicit input. |

Machine-readable reports go to standard output or the requested output file;
operational errors go to standard error. This keeps JSON and SARIF valid when
used in pipelines. The `github` format is intended for workflow standard output
so GitHub can turn its escaped workflow commands into annotations.
