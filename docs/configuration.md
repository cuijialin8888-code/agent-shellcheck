# Repository policy configuration

`agent-shellcheck` works without configuration. Teams that want one shared
policy can add `.agent-shellcheck.json` at the repository root. The file uses
JSON so Python 3.9 through 3.13 can load it without adding a runtime dependency.

```json
{
  "$schema": "https://raw.githubusercontent.com/cuijialin8888-code/agent-shellcheck/v0.2.0/schemas/config.schema.json",
  "version": 1,
  "paths": ["."],
  "target": "portable",
  "minSeverity": "warning",
  "failOn": "error",
  "ignore": [],
  "exclude": ["generated/**", "vendor/**"],
  "maxFiles": 1000
}
```

Start from [the complete example](../examples/agent-shellcheck.example.json).
The optional schema URL enables validation and editor completion; the scanner
never downloads it.

## Discovery and precedence

The CLI looks for `.agent-shellcheck.json` in the current directory, then each
parent directory up to and including the nearest Git root. It does not search
outside that repository. Use `--config PATH` for a specifically named file or
`--no-config` to disable discovery.

Precedence is predictable:

1. explicit command-line values;
2. repository policy;
3. built-in defaults.

If `--ignore` or `--exclude` appears on the command line, that complete CLI
list replaces the configured list. Configured `paths` are resolved relative to
the policy file. Explicit positional paths remain relative to the invoking
shell. For safety, configured paths must remain inside the policy directory;
absolute paths, `..` escapes, symlink escapes, and a symlinked policy file fail
with status `2`. Pass an explicit CLI path when you intentionally need to scan
elsewhere.

Run `agent-shellcheck --show-config` to print the effective paths and policy as
JSON without scanning files. Unknown keys, unknown rule IDs, invalid types, and
unsupported configuration versions fail with exit status `2` instead of being
silently ignored.

## Keys

| Key | Type | Purpose |
|---|---|---|
| `version` | integer | Configuration contract version. Current value: `1`. |
| `paths` | string array | Default files or directories to scan. |
| `target` | string | Default target for generic command snippets. |
| `minSeverity` | string | Lowest severity included in reports. |
| `failOn` | string | Lowest severity that returns status `1`, or `none`. |
| `ignore` | string array | Stable rule IDs to omit. Prefer narrow, reviewed exceptions. |
| `exclude` | string array | Discovery globs to skip. |
| `maxFiles` | integer | Positive upper bound for matching files. |

Configuration changes policy only. It cannot enable command execution, source
rewrites, network access, or unbounded traversal.
