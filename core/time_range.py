from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta


TIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M",
    "%Y/%m/%d",
)


@dataclass
class TimeRange:
    start_time: datetime
    end_time: datetime
    preset: str = "custom"

    @classmethod
    def from_last(cls, value: str, now: datetime | None = None) -> "TimeRange":
        now = now or datetime.now()
        raw = value.strip().lower()
        if raw.endswith("h"):
            delta = timedelta(hours=int(raw[:-1]))
        elif raw.endswith("d"):
            delta = timedelta(days=int(raw[:-1]))
        else:
            raise ValueError("Invalid --last value. Use forms like 1h, 6h, 24h, 7d, 30d.")
        preset = f"last_{raw}"
        return cls(now - delta, now, preset)

    @classmethod
    def preset_range(cls, preset: str, now: datetime | None = None) -> "TimeRange":
        mapping = {
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
        start_dt = parse_datetime(start)
        end_dt = parse_datetime(end)
        if start_dt > end_dt:
            raise ValueError("Start time must be earlier than end time.")
        return cls(start_dt, end_dt, "custom")

    def contains(self, timestamp: datetime | None) -> bool:
        if timestamp is None:
            return False
        if timestamp.tzinfo is not None:
            timestamp = timestamp.replace(tzinfo=None)
        return self.start_time <= timestamp <= self.end_time

    def label(self) -> str:
        return f"{self.preset}: {self.start_time:%Y-%m-%d %H:%M:%S} - {self.end_time:%Y-%m-%d %H:%M:%S}"


def parse_datetime(value: str) -> datetime:
    text = value.strip()
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"Invalid time '{value}'. Expected 'YYYY-MM-DD HH:MM:SS'.") from exc
