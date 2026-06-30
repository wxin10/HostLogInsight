import os
from datetime import datetime

from collectors.file_collector import FileCollector
from core.models import LogSource
from core.time_range import TimeRange


def test_file_collector_bad_line_does_not_crash(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("not a timestamp but still an event\n", encoding="utf-8")
    source = LogSource(os_type="linux", source_type="file", name="app.log", path=str(log), parser="generic")
    events = FileCollector().collect_source(source, TimeRange.custom("2026-01-01 00:00:00", "2026-01-02 00:00:00"))
    assert len(events) == 1
    assert source.attributes["total_lines_read"] == 1


def test_file_collector_size_limit(tmp_path):
    log = tmp_path / "big.log"
    log.write_text("x" * 2048, encoding="utf-8")
    source = LogSource(os_type="linux", source_type="file", name="big.log", path=str(log), parser="generic")
    events = FileCollector(max_file_mb=0).collect_source(source, TimeRange.custom("2026-01-01 00:00:00", "2026-01-02 00:00:00"))
    assert events == []
    assert source.status == "unavailable"


def test_file_collector_mtime_skip(tmp_path):
    log = tmp_path / "old.log"
    log.write_text("2020-01-01 00:00:00 old\n", encoding="utf-8")
    old = datetime(2020, 1, 1).timestamp()
    os.utime(log, (old, old))
    source = LogSource(os_type="linux", source_type="file", name="old.log", path=str(log), parser="generic")
    events = FileCollector().collect_source(source, TimeRange.custom("2026-01-01 00:00:00", "2026-01-02 00:00:00"))
    assert events == []
    assert source.attributes["skipped_reason"] == "mtime_before_time_range"


def test_file_collector_permission_error(monkeypatch, tmp_path):
    log = tmp_path / "denied.log"
    log.write_text("x", encoding="utf-8")
    source = LogSource(os_type="linux", source_type="file", name="denied.log", path=str(log), parser="generic")

    def denied(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr("pathlib.Path.open", denied)
    events = FileCollector().collect_source(source, TimeRange.custom("2026-01-01 00:00:00", "2026-01-02 00:00:00"))
    assert events == []
    assert source.status == "permission_denied"
