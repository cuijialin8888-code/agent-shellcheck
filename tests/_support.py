from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


def write_text(path: Path, text: str, *, newline: str | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline=newline) as handle:
        handle.write(text)
    return path


def run_cli(
    arguments: Iterable[str], *, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        str(SRC_ROOT) if not existing else os.pathsep.join((str(SRC_ROOT), existing))
    )
    return subprocess.run(
        [sys.executable, "-m", "agent_shellcheck", *arguments],
        cwd=cwd or PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
        check=False,
    )


def parsed_stdout(process: subprocess.CompletedProcess[str]) -> dict:
    if not process.stdout.strip():
        raise AssertionError(
            f"CLI produced no JSON; returncode={process.returncode}, stderr={process.stderr!r}"
        )
    return json.loads(process.stdout)


def finding_lines(result) -> set[int]:
    return {finding.line for finding in result.findings}


def findings_on_line(result, line: int):
    return [finding for finding in result.findings if finding.line == line]
