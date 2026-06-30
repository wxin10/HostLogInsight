from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import re


TIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M",
    "%Y/%m/%d",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S%z",
)


@dataclass
class TimeRange:
    start_time: datetime
    end_time: datetime
    preset: str = "custom"

    @classmethod
    def from_last(cls, value: str, now: datetime | None = None) -> "TimeRange":
        now = normalize_datetime(now or datetime.now())
        raw = value.strip().lower().replace(" ", "")
        match = re.fullmatch(r"(\d+)(m|h|d)", raw)
        if not match:
            raise ValueError("Invalid --last value. Use forms like 30m, 1h, 6h, 24h, 7d, 30d.")
        amount = int(match.group(1))
        unit = match.group(2)
        if amount <= 0:
            raise ValueError("--last value must be greater than zero.")
        if unit == "m":
            delta = timedelta(minutes=amount)
        elif unit == "h":
            delta = timedelta(hours=amount)
        else:
            delta = timedelta(days=amount)
        preset = f"last_{amount}{unit}"
        return cls(now - delta, now, preset)

    @classmethod
    def preset_range(cls, preset: str, now: datetime | None = None) -> "TimeRange":
        mapping = {
            "last_30m": "30m",
            "last_1h": "1h",
            "last_6h": "6h",
            "last_24h": "24h",
            "last_7d": "7d",
            "last_30d": "30d",
        }
        if preset not in mapping:
            raise ValueError(f"Unknown time preset: {preset}")
        item = cls.from_last(mapping[preset], now)
        item.preset = preset
        return item

    @classmethod
    def custom(cls, start: str, end: str) -> "TimeRange":
        start_dt = normalize_datetime(parse_datetime(start))
        end_dt = normalize_datetime(parse_datetime(end))
        if start_dt > end_dt:
            raise ValueError("Start time must be earlier than end time.")
        return cls(start_dt, end_dt, "custom")

    def contains(self, timestamp: datetime | None) -> bool:
        if timestamp is None:
            return False
        ts = normalize_datetime(timestamp)
        return self.start_time <= ts <= self.end_time

    def label(self) -> str:
        return f"{self.preset}: {self.start_time:%Y-%m-%d %H:%M:%S} - {self.end_time:%Y-%m-%d %H:%M:%S}"


def normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is not None:
        return value.astimezone().replace(tzinfo=None)
    return value


def parse_datetime(value: str) -> datetime:
    text = value.strip().strip('"').strip("'")
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid time '{value}'. Expected 'YYYY-MM-DD HH:MM:SS' or ISO 8601.") from exc
