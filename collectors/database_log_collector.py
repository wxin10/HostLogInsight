from __future__ import annotations

from collectors.file_collector import FileCollector
from core.models import LogEvent, LogSource
from core.time_range import TimeRange


class DatabaseLogCollector(FileCollector):
    def collect(self, sources: list[LogSource], time_range: TimeRange) -> list[LogEvent]:
        db_sources = [s for s in sources if s.enabled and s.source_type == "database"]
        return super().collect(db_sources, time_range)
