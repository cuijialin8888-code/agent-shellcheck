# Contributing

Thanks for helping instruction files work on more machines.

## Before opening a change

- Search existing issues and keep each proposal focused.
- For a new diagnostic, include one minimal triggering example, one nearby
  non-triggering example, the affected target(s), and an explanation of why the
  signal is reliable.
- For a false positive, use the dedicated issue form. False-positive reduction
  takes priority over adding a broad heuristic.
- Do not add command execution, network access, or automatic rewriting to the
  scanner path.

## Local development

The runtime uses only the Python standard library. From a checkout:

```console
python -m pip install -e .
python -m unittest discover -s tests -v
python -m agent_shellcheck --help
```

Run a targeted smoke test against the included example:

```console
agent-shellcheck examples --target portable
```

## Pull requests

1. Keep the patch small and explain the user-facing behavior.
2. Add or update tests for every behavior change.
3. Update `docs/rules.md` when a diagnostic changes.
4. Preserve stable rule IDs and machine-readable fields.
5. Confirm that tests pass on Windows, Linux, and macOS where relevant.

By contributing, you agree that your contribution is licensed under the MIT
License in this repository.
