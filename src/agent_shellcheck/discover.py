from __future__ import annotations

import fnmatch
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


EXACT_NAMES = {
    ".clinerules",
    ".cursorrules",
    "agents.md",
    "agents.override.md",
    "claude.md",
    "claude.local.md",
    "gemini.md",
    "skill.md",
}
SUFFIXES = (".instructions.md", ".mdc")
SKIP_DIRECTORIES = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "site-packages",
    "target",
    "vendor",
    "venv",
}
MAX_FILE_BYTES = 1_000_000


@dataclass(frozen=True)
class DiscoveryResult:
    root: Path
    files: tuple[Path, ...]
    skipped_files: int


class DiscoveryError(RuntimeError):
    pass


def discover_files(
    inputs: Iterable[str | Path], *, excludes: Iterable[str] = (), max_files: int = 1000
) -> DiscoveryResult:
    if isinstance(max_files, bool) or not isinstance(max_files, int) or max_files < 1:
        raise DiscoveryError("max_files must be a positive integer")
    raw_inputs = [Path(item).expanduser() for item in inputs]
    if not raw_inputs:
        raw_inputs = [Path.cwd()]

    resolved_inputs: list[Path] = []
    for item in raw_inputs:
        try:
            resolved = item.resolve(strict=True)
        except (FileNotFoundError, OSError) as exc:
            raise DiscoveryError(f"input does not exist or cannot be read: {item}") from exc
        resolved_inputs.append(resolved)

    root = _common_root(resolved_inputs)
    patterns = tuple(_normalize_pattern(pattern) for pattern in excludes)
    files: set[Path] = set()
    skipped = 0

    for item in resolved_inputs:
        if item.is_file():
            if _is_markdown_candidate(item, explicit=True):
                if _matches_any(_relative_posix(item, root), patterns):
                    skipped += 1
                    continue
                if item.stat().st_size > MAX_FILE_BYTES:
                    raise DiscoveryError(f"file is larger than {MAX_FILE_BYTES} bytes: {item}")
                files.add(item)
                if len(files) > max_files:
                    raise DiscoveryError(
                        f"more than {max_files} matching files found; narrow the input or raise --max-files"
                    )
            continue
        if not item.is_dir():
            raise DiscoveryError(f"input must be a regular file or directory: {item}")
        for directory, dirnames, filenames in os.walk(item, followlinks=False):
            retained_directories: list[str] = []
            for name in sorted(dirnames):
                candidate = Path(directory, name)
                candidate_relative = _relative_posix(candidate, root)
                if name.casefold() in SKIP_DIRECTORIES or candidate.is_symlink():
                    continue
                if _matches_any(candidate_relative, patterns) or _matches_any(
                    candidate_relative + "/", patterns
                ):
                    # Count the excluded subtree as one bounded skip without walking it.
                    skipped += 1
                    continue
                retained_directories.append(name)
            dirnames[:] = retained_directories
            for filename in sorted(filenames):
                path = Path(directory, filename)
                if not _is_markdown_candidate(path, explicit=False):
                    continue
                relative = _relative_posix(path, root)
                if _matches_any(relative, patterns):
                    skipped += 1
                    continue
                try:
                    status = path.stat()
                    if path.is_symlink() or not stat.S_ISREG(status.st_mode) or status.st_size > MAX_FILE_BYTES:
                        skipped += 1
                        continue
                except OSError:
                    skipped += 1
                    continue
                files.add(path.resolve())
                if len(files) > max_files:
                    raise DiscoveryError(
                        f"more than {max_files} matching files found; narrow the input or raise --max-files"
                    )

    ordered = tuple(sorted(files, key=lambda value: (
        _relative_posix(value, root).casefold(), _relative_posix(value, root)
    )))
    return DiscoveryResult(root=root, files=ordered, skipped_files=skipped)


def relative_path(path: Path, root: Path) -> str:
    return _relative_posix(path, root)


def read_text(path: Path) -> str:
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise DiscoveryError(f"input must be a regular file: {path}")
        with path.open("rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise DiscoveryError(f"cannot read instruction file: {path}") from exc
    if len(data) > MAX_FILE_BYTES:
        raise DiscoveryError(f"file is larger than {MAX_FILE_BYTES} bytes: {path}")
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DiscoveryError(f"file is not valid UTF-8: {path}") from exc


def _common_root(items: list[Path]) -> Path:
    directories = [item if item.is_dir() else item.parent for item in items]
    try:
        return Path(os.path.commonpath([str(item) for item in directories])).resolve()
    except ValueError:
        return directories[0].resolve()


def _is_markdown_candidate(path: Path, *, explicit: bool) -> bool:
    if explicit:
        return path.suffix.casefold() in {".md", ".mdc", ".markdown"} or path.name.casefold() in EXACT_NAMES
    name = path.name.casefold()
    return name in EXACT_NAMES or name.endswith(SUFFIXES)


def _normalize_pattern(pattern: str) -> str:
    return pattern.replace("\\", "/").removeprefix("./")


def _relative_posix(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _matches_any(relative: str, patterns: tuple[str, ...]) -> bool:
    return any(
        fnmatch.fnmatchcase(relative, pattern)
        or fnmatch.fnmatchcase(relative.casefold(), pattern.casefold())
        for pattern in patterns
    )
