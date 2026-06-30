from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


BASE_DIR = Path(__file__).resolve().parents[1]
RESOURCE_DIR = BASE_DIR / "resources"
USER_CONFIG = Path.home() / ".hostloginsight.json"


def load_default_paths() -> dict[str, Any]:
    with (RESOURCE_DIR / "default_paths.yaml").open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def load_user_paths() -> list[str]:
    if not USER_CONFIG.exists():
        return []
    try:
        data = json.loads(USER_CONFIG.read_text(encoding="utf-8"))
        return list(data.get("paths", []))
    except Exception:
        return []


def save_user_paths(paths: list[str]) -> None:
    USER_CONFIG.write_text(json.dumps({"paths": sorted(set(paths))}, ensure_ascii=False, indent=2), encoding="utf-8")
