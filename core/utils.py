from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable


IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def safe_read_text(path: Path, encodings: Iterable[str] = ("utf-8", "gbk", "latin-1")) -> str:
    last_error = ""
    for encoding in encodings:
        try:
            return path.read_text(encoding=encoding, errors="replace")
        except Exception as exc:
            last_error = str(exc)
    raise OSError(last_error)


def first_ip(text: str) -> str:
    match = IP_RE.search(text or "")
    return match.group(0) if match else ""


def contains_any(text: str, keywords: Iterable[str]) -> bool:
    low = (text or "").lower()
    return any(k.lower() in low for k in keywords)


def event_evidence(event) -> dict:
    return {
        "event_id": getattr(event, "event_id", ""),
        "timestamp": getattr(event, "timestamp", None).isoformat() if getattr(event, "timestamp", None) else None,
        "source": getattr(event, "source_name", ""),
        "raw": getattr(event, "raw", "")[:4000],
    }


def stable_hash(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


def json_dumps(data) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)


def parse_int(value: str | int | None, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def coerce_datetime(value) -> datetime | None:
    if isinstance(value, datetime):
        return value
    return None
