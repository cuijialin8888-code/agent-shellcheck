# Continuous integration

## Simple check

Pin a release in CI so a rule update cannot unexpectedly change an existing
workflow:

```yaml
name: Instruction portability

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  agent-shellcheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: cuijialin8888-code/agent-shellcheck@v0.1.0
        with:
          args: ". --target portable"
```

The action installs the pinned checkout without runtime dependencies, then runs
the scanner. Analysis is offline and does not execute commands discovered in
instruction files. Fetching the action and Python package source is handled by
the workflow runner before analysis.

## GitHub code scanning with SARIF

This variant publishes line annotations in GitHub's code-scanning interface:

```yaml
name: Instruction portability

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - name: Produce SARIF
        uses: cuijialin8888-code/agent-shellcheck@v0.1.0
        with:
          args: ". --target portable --format sarif --output agent-shellcheck.sarif"
        continue-on-error: true
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: agent-shellcheck.sarif
```

`continue-on-error` lets the upload step run when findings produce a non-zero
status; code scanning still displays the diagnostics. Adjust repository policy
if findings should fail the job immediately.

## Review-friendly Markdown

Write a report into the GitHub Actions job summary:

```yaml
- name: Scan instruction files
  id: instructions
  uses: cuijialin8888-code/agent-shellcheck@v0.1.0
  continue-on-error: true
  with:
    args: ". --target portable --format markdown --output report.md"
- name: Add report to the job summary
  if: always()
  shell: bash
  run: cat report.md >> "$GITHUB_STEP_SUMMARY"
- name: Enforce the result
  if: steps.instructions.outcome == 'failure'
  shell: bash
  run: exit 1
```

The HTML format is self-contained and can be uploaded as an artifact when a
long-lived, offline report is useful.
