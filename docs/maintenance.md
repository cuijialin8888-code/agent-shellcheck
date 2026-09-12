# Maintenance checklist

Keep the scanner static, deterministic, offline, and free of runtime dependencies.

## Routine checks

- Preserve the no-command-execution boundary: discovered shell text is data, never a script to run.
- When adding a rule, include a minimal triggering fixture, a nearby non-triggering case, stable rule documentation, and regression coverage.
- Keep the composite action, configuration schema, CLI reference, and README examples aligned.
- For releases, inspect the wheel, source distribution, action metadata, and checksum assets before publishing.

## Review log

- 2026-09-12: reviewed public `main`, open Issues/PRs, and recent Actions; no open Issues/PRs were present, and the latest main-branch CI run (`34128196248`) and Release run (`34128320819`) completed successfully.
