from __future__ import annotations

import json
from pathlib import Path

from .models import Finding


MAX_BASELINE_BYTES = 5_000_000


class BaselineError(ValueError):
    """A baseline file is unreadable or is not an agent-shellcheck report."""


def finding_key(finding: Finding) -> tuple[str, str, str, str]:
    """Return a line-independent identity for a finding."""

    return (
        finding.rule_id,
        finding.relative_path.replace("\\", "/"),
        finding.message,
        finding.evidence,
    )


def load_baseline(path: Path) -> set[tuple[str, str, str, str]]:
    """Load finding identities from a previous JSON report."""

    candidate = path.expanduser()
    if candidate.is_symlink():
        raise BaselineError(f"baseline file cannot be a symbolic link: {candidate}")
    try:
        size = candidate.stat().st_size
    except OSError as exc:
        raise BaselineError(f"cannot stat baseline file {candidate}: {exc}") from exc
    if size > MAX_BASELINE_BYTES:
        raise BaselineError(f"baseline file is larger than {MAX_BASELINE_BYTES} bytes: {candidate}")
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineError(f"cannot read baseline JSON {candidate}: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
        raise BaselineError("baseline must be an agent-shellcheck JSON report with a findings array")

    keys: set[tuple[str, str, str, str]] = set()
    for index, item in enumerate(payload["findings"]):
        if not isinstance(item, dict):
            raise BaselineError(f"baseline finding {index} must be an object")
        values = tuple(item.get(name) for name in ("ruleId", "path", "message", "evidence"))
        if any(not isinstance(value, str) for value in values):
            raise BaselineError(
                f"baseline finding {index} must contain string ruleId, path, message, and evidence"
            )
        keys.add((values[0], values[1].replace("\\", "/"), values[2], values[3]))
    return keys
