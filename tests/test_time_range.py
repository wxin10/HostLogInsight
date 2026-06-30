from datetime import datetime

from core.time_range import TimeRange, parse_datetime


def test_last_24h_contains_now():
    now = datetime(2026, 1, 2, 12, 0, 0)
    tr = TimeRange.from_last("24h", now)
    assert tr.contains(datetime(2026, 1, 2, 11, 0, 0))
    assert not tr.contains(datetime(2026, 1, 1, 11, 59, 59))


def test_last_30m_contains_recent():
    now = datetime(2026, 1, 2, 12, 0, 0)
    tr = TimeRange.from_last("30m", now)
    assert tr.contains(datetime(2026, 1, 2, 11, 45, 0))
    assert not tr.contains(datetime(2026, 1, 2, 11, 20, 0))


def test_parse_datetime_clear_format():
    assert parse_datetime("2025-01-01 00:00:00").year == 2025


def test_custom_iso_and_start_after_end():
    tr = TimeRange.custom("2025-01-01T00:00:00", "2025-01-01T01:00:00")
    assert tr.contains(datetime(2025, 1, 1, 0, 30, 0))
    try:
        TimeRange.custom("2025-01-02 00:00:00", "2025-01-01 00:00:00")
    except ValueError:
        return
    raise AssertionError("start > end should fail")
