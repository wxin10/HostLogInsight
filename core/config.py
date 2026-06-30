from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import yaml


BASE_DIR = Path(__file__).resolve().parents[1]
RESOURCE_DIR = BASE_DIR / "resources"
def user_config_path() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return root / "HostLogInsight" / "user_paths.json"


USER_CONFIG = user_config_path()


def load_default_paths() -> dict[str, Any]:
    with (RESOURCE_DIR / "default_paths.yaml").open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def load_user_path_entries() -> list[dict[str, Any]]:
    if not USER_CONFIG.exists():
        return []
    try:
        data = json.loads(USER_CONFIG.read_text(encoding="utf-8"))
        paths = data.get("paths", [])
        entries = []
        for item in paths:
            if isinstance(item, str):
                entries.append({"path": item, "enabled": True, "added_time": ""})
            elif isinstance(item, dict) and item.get("path"):
                entries.append({"path": item["path"], "enabled": bool(item.get("enabled", True)), "added_time": item.get("added_time", "")})
        return entries
    except Exception:
        return []


def load_user_paths() -> list[str]:
    return [entry["path"] for entry in load_user_path_entries() if entry.get("enabled", True)]


def save_user_paths(paths: list[str]) -> None:
    from datetime import datetime

    existing = {entry["path"]: entry for entry in load_user_path_entries()}
    entries = []
    for path in sorted(set(paths)):
        entry = existing.get(path, {})
        entries.append({"path": path, "enabled": bool(entry.get("enabled", True)), "added_time": entry.get("added_time") or datetime.now().isoformat(timespec="seconds")})
    save_user_path_entries(entries)


def save_user_path_entries(entries: list[dict[str, Any]]) -> None:
    USER_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    cleaned = []
    for entry in entries:
        if entry.get("path"):
            cleaned.append({"path": entry["path"], "added_time": entry.get("added_time", ""), "enabled": bool(entry.get("enabled", True))})
    USER_CONFIG.write_text(json.dumps({"paths": cleaned}, ensure_ascii=False, indent=2), encoding="utf-8")
