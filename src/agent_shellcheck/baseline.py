from __future__ import annotations

import json
import stat
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
        status = candidate.stat()
    except OSError as exc:
        raise BaselineError(f"cannot stat baseline file {candidate}: {exc}") from exc
    if not stat.S_ISREG(status.st_mode):
        raise BaselineError(f"baseline input must be a regular file: {candidate}")
    if status.st_size > MAX_BASELINE_BYTES:
        raise BaselineError(f"baseline file is larger than {MAX_BASELINE_BYTES} bytes: {candidate}")
    try:
        with candidate.open("rb") as handle:
            data = handle.read(MAX_BASELINE_BYTES + 1)
        if len(data) > MAX_BASELINE_BYTES:
            raise BaselineError(f"baseline file grew beyond {MAX_BASELINE_BYTES} bytes: {candidate}")
        payload = json.loads(data.decode("utf-8-sig"))
    except RecursionError as exc:
        raise BaselineError("baseline JSON nesting exceeds the parser limit") from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineError(f"cannot read baseline JSON {candidate}: {exc}") from exc
    except BaselineError:
        raise
    except ValueError as exc:
        raise BaselineError("baseline JSON exceeds the parser limits") from exc
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
