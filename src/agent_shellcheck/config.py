from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from .rules import TARGETS


CONFIG_NAME = ".agent-shellcheck.json"
CONFIG_VERSION = 1
MAX_CONFIG_BYTES = 1_000_000
DEFAULT_TARGET = "auto"
DEFAULT_MIN_SEVERITY = "info"
DEFAULT_FAIL_ON = "error"
DEFAULT_MAX_FILES = 1000

_ALLOWED_KEYS = {
    "$schema",
    "version",
    "paths",
    "target",
    "minSeverity",
    "failOn",
    "ignore",
    "exclude",
    "maxFiles",
}
_SEVERITIES = {"info", "warning", "error"}
_FAIL_LEVELS = _SEVERITIES | {"none"}


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class ProjectConfig:
    source: Path | None = None
    paths: tuple[str, ...] = ()
    target: str | None = None
    min_severity: str | None = None
    fail_on: str | None = None
    ignore: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    max_files: int | None = None

    def resolved_paths(self) -> list[Path]:
        if self.source is None:
            return [Path(value).expanduser() for value in self.paths]
        base = self.source.parent.resolve()
        resolved: list[Path] = []
        for value in self.paths:
            path = Path(value).expanduser()
            if path.is_absolute():
                raise ConfigError(
                    f"configured path must be relative to the policy directory: {value}"
                )
            candidate = (base / path).resolve()
            try:
                candidate.relative_to(base)
            except ValueError as exc:
                raise ConfigError(
                    f"configured path escapes the policy directory: {value}"
                ) from exc
            resolved.append(candidate)
        return resolved


def load_project_config(
    *, explicit: Path | None = None, disabled: bool = False, cwd: Path | None = None
) -> ProjectConfig:
    working_directory = (cwd or Path.cwd()).resolve()
    if disabled:
        if explicit is not None:
            raise ConfigError("--config and --no-config cannot be used together")
        return ProjectConfig()

    if explicit is not None:
        path = explicit.expanduser()
        if not path.is_absolute():
            path = working_directory / path
        if path.is_symlink():
            raise ConfigError(f"configuration file cannot be a symbolic link: {path}")
        path = path.resolve()
        if not path.is_file():
            raise ConfigError(f"configuration file does not exist or is not a file: {path}")
    else:
        path = find_project_config(working_directory)
        if path is None:
            return ProjectConfig()

    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ConfigError(f"cannot stat configuration file {path}: {exc}") from exc
    if size > MAX_CONFIG_BYTES:
        raise ConfigError(f"configuration file is larger than {MAX_CONFIG_BYTES} bytes: {path}")
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise ConfigError(f"cannot read configuration file {path}: {exc}") from exc
    if len(data) > MAX_CONFIG_BYTES:
        raise ConfigError(f"configuration file grew beyond {MAX_CONFIG_BYTES} bytes: {path}")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"configuration file is not valid UTF-8: {path}") from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"invalid JSON in {path} at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    return _parse_config(payload, path)


def find_project_config(start: Path) -> Path | None:
    current = start.resolve()
    while True:
        candidate = current / CONFIG_NAME
        if candidate.is_file():
            if candidate.is_symlink():
                raise ConfigError(f"configuration file cannot be a symbolic link: {candidate}")
            return candidate.resolve()
        if (current / ".git").exists() or current.parent == current:
            return None
        current = current.parent


def _parse_config(payload: Any, path: Path) -> ProjectConfig:
    if not isinstance(payload, dict):
        raise ConfigError(f"configuration root must be a JSON object: {path}")
    unknown = sorted(str(key) for key in payload if key not in _ALLOWED_KEYS)
    if unknown:
        raise ConfigError("unknown configuration key(s): " + ", ".join(unknown))

    schema = payload.get("$schema")
    if schema is not None and not isinstance(schema, str):
        raise ConfigError("configuration key '$schema' must be a string")

    version = payload.get("version", CONFIG_VERSION)
    if isinstance(version, bool) or not isinstance(version, int) or version != CONFIG_VERSION:
        raise ConfigError(f"unsupported configuration version: {version!r}; expected {CONFIG_VERSION}")

    target = _optional_choice(payload, "target", set(TARGETS))
    min_severity = _optional_choice(payload, "minSeverity", _SEVERITIES)
    fail_on = _optional_choice(payload, "failOn", _FAIL_LEVELS)
    max_files = payload.get("maxFiles")
    if max_files is not None and (
        isinstance(max_files, bool) or not isinstance(max_files, int) or max_files < 1
    ):
        raise ConfigError("configuration key 'maxFiles' must be an integer of at least 1")

    return ProjectConfig(
        source=path,
        paths=_string_list(payload, "paths", allow_empty=False),
        target=target,
        min_severity=min_severity,
        fail_on=fail_on,
        ignore=_string_list(payload, "ignore", uppercase=True),
        exclude=_string_list(payload, "exclude"),
        max_files=max_files,
    )


def _optional_choice(payload: dict[str, Any], key: str, choices: set[str]) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or value not in choices:
        rendered = ", ".join(sorted(choices))
        raise ConfigError(f"configuration key {key!r} must be one of: {rendered}")
    return value


def _string_list(
    payload: dict[str, Any], key: str, *, uppercase: bool = False, allow_empty: bool = True
) -> tuple[str, ...]:
    value = payload.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError(f"configuration key {key!r} must be an array of strings")
    normalized: list[str] = []
    for item in value:
        candidate = item.strip()
        if not candidate and not allow_empty:
            raise ConfigError(f"configuration key {key!r} cannot contain an empty path")
        if not candidate:
            raise ConfigError(f"configuration key {key!r} cannot contain an empty value")
        candidate = candidate.upper() if uppercase else candidate
        if candidate not in normalized:
            normalized.append(candidate)
    return tuple(normalized)
