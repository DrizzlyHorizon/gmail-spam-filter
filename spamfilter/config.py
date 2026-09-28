"""Loads settings: config.example.toml as defaults, overlaid by data/config.toml."""
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _merge(base, override):
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


def load_config(data_dir):
    with open(ROOT / "config.example.toml", "rb") as f:
        cfg = tomllib.load(f)
    user_file = Path(data_dir) / "config.toml"
    if user_file.exists():
        with open(user_file, "rb") as f:
            _merge(cfg, tomllib.load(f))
    return cfg
