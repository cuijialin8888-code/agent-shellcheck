# Security policy

## Supported versions

Security fixes are applied to the latest released minor version. This project
is currently in the `0.x` series, so users should upgrade to the newest release
before reporting a reproducible issue.

## Reporting a vulnerability

Please use GitHub's **Report a vulnerability** flow on the Security tab. Do
not open a public issue for a vulnerability that could put users at risk.

Include the affected version, platform, a minimal reproducer, expected impact,
and any suggested mitigation. You should receive an acknowledgement within
seven days. If private reporting is unavailable, open a public issue containing
only a request for a private contact channel—do not include exploit details.

## Trust boundary

`agent-shellcheck` treats instruction files as untrusted text. A normal scan:

- reads candidate instruction files;
- parses Markdown structure and command-like snippets;
- emits deterministic diagnostics; and
- never executes the commands it finds.

It is a portability linter, not a sandbox, malware detector, or complete
security scanner. Review third-party instructions before running them.

## Input resource limits

Instruction reads are capped at 1,000,000 bytes and baseline reads at 5,000,000 bytes,
including when files grow after their initial size check. Nonregular candidates
(such as named pipes) are skipped during directory discovery and rejected by direct
readers. Exclusions and the file cap apply to explicit file inputs as well.
The scanner does not defend against hostile filesystem replacement races; keep
inputs stable while scanning. These limits do not guarantee a fixed memory budget.
