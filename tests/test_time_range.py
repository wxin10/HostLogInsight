from datetime import datetime

from core.time_range import TimeRange, parse_datetime


def test_last_24h_contains_now():
    now = datetime(2026, 1, 2, 12, 0, 0)
    tr = TimeRange.from_last("24h", now)
    assert tr.contains(datetime(2026, 1, 2, 11, 0, 0))
    assert not tr.contains(datetime(2026, 1, 1, 11, 59, 59))


def test_parse_datetime_clear_format():
    assert parse_datetime("2025-01-01 00:00:00").year == 2025
