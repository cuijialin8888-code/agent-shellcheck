# Adopt agent-shellcheck in CI

`agent-shellcheck` is a static, offline, read-only check for shell and path assumptions inside agent instructions. It never executes commands found in Markdown.

Commit `.agent-shellcheck.json` when the repository needs one shared policy. CLI arguments override repository values; `--show-config` inspects the effective policy without scanning and `--no-config` provides a clean command-line run.

For the composite action, request only read permission and native annotations: use `cuijialin8888-code/agent-shellcheck@v0.2.0` with `args: ". --target portable --format github"`. In security-sensitive workflows, replace the tag with the reviewed commit SHA and keep the version in a comment.

Use the exact file, line, shell target, and stable rule ID as the review starting point. Keep `--min-severity` separate from `--fail-on`, and add a triggering plus non-triggering fixture for rule changes. Use this tool alongside ShellCheck, PSScriptAnalyzer, tests, and security review.