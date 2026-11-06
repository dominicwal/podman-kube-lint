"""Load and validate optional scanner configuration."""

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .yaml_loader import Loader


class ConfigError(ValueError):
    """A configuration file cannot be read or contains invalid settings."""


@dataclass
class Config:
    paths: list[str] = field(default_factory=lambda: ["."])
    exclude: list[str] = field(default_factory=list)
    skip_dirs: list[str] = field(default_factory=list)
    fail_on: str = "error"
    all_kinds: bool = False
    format: str = "text"


def load_config(path: str) -> Config:
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
        loader = Loader(text)
        try:
            data = loader.get_single_data()
            duplicates = loader.dups
        finally:
            loader.dispose()
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"Cannot read configuration {path!r}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError("Configuration must be a YAML mapping.")
    if duplicates:
        raise ConfigError(f"Duplicate configuration key: {duplicates[0][0]!r}")
    allowed = {"paths", "exclude", "skip_dirs", "fail_on", "all_kinds", "format"}
    unknown = set(data) - allowed
    if unknown:
        raise ConfigError(f"Unknown configuration key: {next(iter(unknown))!r}")

    for key in ("paths", "exclude", "skip_dirs"):
        if key in data:
            values = data[key]
            if not isinstance(values, list) or not all(isinstance(v, str) and v for v in values):
                raise ConfigError(f"'{key}' must be a list of non-empty strings.")
            if key == "paths" and not values:
                raise ConfigError("'paths' must contain at least one path.")
            if key == "skip_dirs" and any(v in (".", "..") or "/" in v or "\\" in v for v in values):
                raise ConfigError("'skip_dirs' entries must be directory names, not paths.")

    for key, choices in (("fail_on", ("error", "warning", "never")), ("format", ("text", "json"))):
        if key in data and (not isinstance(data[key], str) or data[key] not in choices):
            raise ConfigError(f"'{key}' must be one of: {', '.join(choices)}.")
    if "all_kinds" in data and not isinstance(data["all_kinds"], bool):
        raise ConfigError("'all_kinds' must be a boolean.")
    return Config(**data)
